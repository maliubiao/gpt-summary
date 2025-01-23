Response:
Let's break down the thought process for answering the request about `go/src/strconv/atoi.go`.

**1. Understanding the Core Request:**

The fundamental goal is to analyze the provided Go code snippet and explain its functionality, illustrate its usage, highlight potential pitfalls, and discuss any command-line argument handling.

**2. Initial Code Inspection and Keyword Identification:**

Scanning the code reveals key identifiers like `ParseUint`, `ParseInt`, `Atoi`, `NumError`, `ErrRange`, `ErrSyntax`, `base`, `bitSize`, and functions like `lower`, `syntaxError`, `rangeError`, etc. These immediately suggest the code is about string-to-integer conversions.

**3. Deeper Dive into Key Functions:**

* **`lower(c byte)`:**  This is a utility function for case-insensitive character comparison. It's a helper for parsing different number bases (like hexadecimal).

* **`ErrRange`, `ErrSyntax`, `NumError`:** These are standard error handling mechanisms. `NumError` specifically carries details about the failed conversion (function name, input, error type).

* **`ParseUint(s string, base int, bitSize int)`:** This is the core unsigned integer parsing function. I notice the logic for handling different bases (including automatic base detection for base 0) and bit sizes. The handling of underscores as digit separators is also apparent.

* **`ParseInt(s string, base int, bitSize int)`:**  This function builds upon `ParseUint` to handle signed integers. It checks for leading signs and then calls `ParseUint`. Range checks are crucial here.

* **`Atoi(s string)`:** This is a convenience function specifically for converting strings to `int` with base 10. The code has a "fast path" for small integers, which is an interesting optimization.

* **`underscoreOK(s string)`:** This helper validates the placement of underscores in the input string when `base` is 0.

**4. Inferring Overall Functionality:**

Based on the analysis of the individual components, the main purpose of this code is to provide robust and flexible functions for converting strings to integer types (both signed and unsigned) in Go. The functions handle various bases, bit sizes, and error conditions.

**5. Illustrative Go Code Examples:**

To demonstrate the functionality, I need examples for each key function:

* **`ParseUint`:**  Demonstrate different bases (decimal, binary, octal, hexadecimal), different `bitSize` values, and how it handles errors.

* **`ParseInt`:** Show signed numbers, different bases, `bitSize`, and error handling (especially range errors).

* **`Atoi`:**  A simple example showcasing the most common use case.

**6. Reasoning about Go Language Features:**

The code utilizes several core Go features:

* **Error Handling:** The `error` interface and custom error types (`NumError`) are standard Go practices.
* **String/Byte Manipulation:**  Working with strings as byte slices (`[]byte(s)`) is common for performance reasons in parsing.
* **Control Flow:** `switch` statements for base detection, `for` loops for iterating through string characters.
* **Constants:**  `maxUint64`, `IntSize` are used for boundary checks and type awareness.
* **Bitwise Operations:** The `lower` function uses bitwise OR for case conversion. Bit shifting (`<<`) is used for calculating maximum values based on `bitSize`.

**7. Considering Command-Line Arguments:**

Reviewing the code, there's no explicit handling of `os.Args` or the `flag` package. The functions are designed for direct use within Go programs, not for parsing command-line input directly. Therefore, the answer should clearly state that this code *doesn't* handle command-line arguments.

**8. Identifying Potential User Errors:**

Thinking about how developers might misuse these functions leads to a few key points:

* **Incorrect Base:**  Providing an invalid base (outside the range 0, 2-36).
* **Incorrect Bit Size:**  Using an invalid `bitSize` (less than 0 or greater than 64).
* **Out-of-Range Values:**  Supplying a string that represents a number too large or too small for the specified `bitSize`.
* **Syntax Errors:**  Including invalid characters (other than digits for the given base, or incorrectly placed underscores).

**9. Structuring the Answer:**

Organize the information logically:

* **Functionality Summary:**  Start with a high-level overview.
* **Detailed Function Explanations:** Explain `ParseUint`, `ParseInt`, and `Atoi` individually.
* **Go Feature Illustration:**  Provide the Go code examples.
* **Code Reasoning:** Explain the underlying Go concepts used.
* **Command-Line Arguments:**  Explicitly address the lack of command-line handling.
* **Common Mistakes:**  List the potential pitfalls for users.
* **Language:**  Use clear and concise Chinese, as requested.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level byte manipulation. It's important to step back and describe the overall purpose first.
*  I needed to ensure the Go code examples were correct and covered the different scenarios (bases, bit sizes, errors).
*  It's crucial to be precise about the command-line argument aspect – stating clearly that it's *not* handled is better than simply omitting it.
* Double-checking the error conditions and how they are reported through `NumError` is important for accuracy.

By following these steps, combining code analysis with an understanding of the request's requirements, I can construct a comprehensive and accurate answer.
这段代码是 Go 语言标准库 `strconv` 包中 `atoi.go` 文件的一部分，它主要实现了将字符串转换为整数的功能。具体来说，它实现了以下几个核心功能：

1. **`lower(c byte)`:**  这是一个辅助函数，用于将一个字节（字符）转换为小写。它的作用是方便进行大小写不敏感的比较，例如在识别十六进制数字 'a' 到 'f' 时。

2. **错误类型定义 (`ErrRange`, `ErrSyntax`, `NumError`)**:
   - `ErrRange`: 定义了一个错误，表示转换的值超出了目标类型的范围。
   - `ErrSyntax`: 定义了一个错误，表示输入的字符串不符合目标类型的语法规则。
   - `NumError`: 定义了一个结构体，用于记录转换失败的详细信息，包括失败的函数名 (`Func`）、输入的字符串 (`Num`) 和具体的错误原因 (`Err`)。它实现了 `error` 接口，并提供了 `Error()` 和 `Unwrap()` 方法，用于生成错误消息和获取底层错误。

3. **错误构造函数 (`syntaxError`, `rangeError`, `baseError`, `bitSizeError`)**:  这些是辅助函数，用于快速创建特定类型的 `NumError` 实例，并自动克隆输入字符串以避免潜在的逃逸分析问题。

4. **常量定义 (`intSize`, `IntSize`, `maxUint64`)**:
   - `intSize`:  根据系统架构（32 位或 64 位）确定 `int` 和 `uint` 类型的大小（以位为单位）。
   - `IntSize`:  导出的常量，与 `intSize` 的值相同，表示 `int` 或 `uint` 类型的位数。
   - `maxUint64`:  定义了 `uint64` 类型的最大值。

5. **`ParseUint(s string, base int, bitSize int) (uint64, error)`**:  这是将字符串 `s` 转换为无符号整数的核心函数。
   - `base`:  指定进制，可以是 0 或 2 到 36。如果为 0，则根据字符串前缀自动判断（"0b" 为二进制，"0o" 或 "0" 开头为八进制，"0x" 为十六进制，否则为十进制）。
   - `bitSize`: 指定结果必须能放入的整数类型的大小（0, 8, 16, 32, 64 分别对应 `uint`, `uint8`, `uint16`, `uint32`, `uint64`）。如果为 0，则使用默认大小（`IntSize`）。
   - 该函数会处理前缀（例如 "0x"），检查进制是否有效，根据进制转换字符串为 `uint64`，并检查是否超出指定 `bitSize` 的范围。它还支持在 `base` 为 0 时使用下划线作为数字分隔符。

6. **`ParseInt(s string, base int, bitSize int) (int64, error)`**: 这是将字符串 `s` 转换为有符号整数的核心函数。
   - 参数含义与 `ParseUint` 相同。
   - 该函数首先处理可选的符号前缀（"+" 或 "-"），然后调用 `ParseUint` 将剩余部分转换为无符号整数。
   - 之后，它会根据符号和指定的 `bitSize` 检查结果是否超出有符号整数的范围。

7. **`Atoi(s string) (int, error)`**: 这是一个便捷函数，相当于调用 `ParseInt(s, 10, 0)`，将字符串 `s` 转换为十进制的 `int` 类型。
   - 为了性能优化，对于较小的、可以放入 `int` 类型的十进制数字，它提供了一个快速路径，直接进行转换，避免调用 `ParseInt` 的完整逻辑。

8. **`underscoreOK(s string) bool`**: 这是一个辅助函数，用于检查字符串 `s` 中下划线的使用是否符合 Go 语言的整数字面量规范。它只在 `ParseInt` 和 `ParseUint` 中 `base` 为 0 时被调用。下划线只能出现在数字之间或进制前缀和数字之间。

**推理其实现的 Go 语言功能：**

这段代码实现了 Go 语言中字符串到整数的转换功能，具体对应于标准库 `strconv` 包中的以下函数：

- `strconv.ParseUint()`
- `strconv.ParseInt()`
- `strconv.Atoi()`

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	// 使用 ParseUint 将不同进制的字符串转换为 uint64
	uintVal, err := strconv.ParseUint("100", 10, 64) // 十进制
	fmt.Printf("ParseUint(\"100\", 10, 64): value = %d, error = %v\n", uintVal, err)

	uintVal, err = strconv.ParseUint("0b1010", 0, 64) // 二进制 (base 0 自动识别)
	fmt.Printf("ParseUint(\"0b1010\", 0, 64): value = %d, error = %v\n", uintVal, err)

	uintVal, err = strconv.ParseUint("0xFF", 0, 32) // 十六进制 (base 0 自动识别, bitSize 32)
	fmt.Printf("ParseUint(\"0xFF\", 0, 32): value = %d, error = %v\n", uintVal, err)

	uintVal, err = strconv.ParseUint("1_000_000", 0, 64) // 带下划线的十进制 (base 0 允许下划线)
	fmt.Printf("ParseUint(\"1_000_000\", 0, 64): value = %d, error = %v\n", uintVal, err)

	// 使用 ParseInt 将不同进制的字符串转换为 int64
	intVal, err := strconv.ParseInt("-123", 10, 64) // 十进制
	fmt.Printf("ParseInt(\"-123\", 10, 64): value = %d, error = %v\n", intVal, err)

	intVal, err = strconv.ParseInt("+0o77", 0, 32) // 八进制 (base 0 自动识别)
	fmt.Printf("ParseInt(\"+0o77\", 0, 32): value = %d, error = %v\n", intVal, err)

	// 使用 Atoi 将字符串转换为 int
	intValAtoi, err := strconv.Atoi("456")
	fmt.Printf("Atoi(\"456\"): value = %d, error = %v\n", intValAtoi, err)

	// 错误示例
	_, err = strconv.Atoi("abc")
	fmt.Printf("Atoi(\"abc\"): error = %v\n", err)

	_, err = strconv.ParseInt("999999999999999999999", 10, 64) // 超出范围
	fmt.Printf("ParseInt(\"999...\"): error = %v\n", err)
}
```

**假设的输入与输出：**

| 函数                          | 输入        | 预期输出 (值, 错误)                                    |
| ----------------------------- | ----------- | ------------------------------------------------------- |
| `strconv.ParseUint`         | `"10"`, `10`, `8`   | `(10, nil)`                                             |
| `strconv.ParseUint`         | `"ff"`, `16`, `16`  | `(255, nil)`                                            |
| `strconv.ParseUint`         | `"100"`, `2`, `64`  | `(4, nil)`                                              |
| `strconv.ParseUint`         | `"12"`, `8`, `64`   | `(10, nil)`                                             |
| `strconv.ParseUint`         | `"10"`, `10`, `4`   | `(10, strconv.ErrRange)` (超出 uint4 范围)             |
| `strconv.ParseUint`         | `"abc"`, `10`, `64`  | `(0, strconv.ErrSyntax)` (无效字符)                     |
| `strconv.ParseInt`          | `"-10"`, `10`, `8`  | `(-10, nil)`                                            |
| `strconv.ParseInt`          | `"+10"`, `10`, `8`  | `(10, nil)`                                             |
| `strconv.ParseInt`          | `"ff"`, `16`, `16`  | `(255, nil)` (十六进制可以解析为正数)                    |
| `strconv.ParseInt`          | `"-80"`, `10`, `7`  | `(-64, strconv.ErrRange)` (超出 int7 范围)             |
| `strconv.ParseInt`          | `"abc"`, `10`, `64`  | `(0, strconv.ErrSyntax)`                                |
| `strconv.Atoi`              | `"123"`     | `(123, nil)`                                            |
| `strconv.Atoi`              | `"-456"`    | `(-456, nil)`                                           |
| `strconv.Atoi`              | `"10a"`     | `(0, strconv.ErrSyntax)`                                |
| `strconv.Atoi`              | `"9999999999"` (假设超出 int 范围) | `(很大的值或很小的值, strconv.ErrRange)` (取决于平台) |

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它的功能是提供用于字符串到整数转换的函数，这些函数可以在程序的其他部分被调用，而程序的其他部分可能会处理命令行参数。

要处理命令行参数，通常会使用 Go 语言标准库的 `flag` 包或者直接解析 `os.Args` 切片。

例如，使用 `flag` 包：

```go
package main

import (
	"flag"
	"fmt"
	"strconv"
)

func main() {
	var numberStr string
	flag.StringVar(&numberStr, "number", "", "The number to convert")
	flag.Parse()

	if numberStr == "" {
		fmt.Println("Please provide a number using the -number flag.")
		return
	}

	num, err := strconv.Atoi(numberStr)
	if err != nil {
		fmt.Printf("Error converting '%s': %v\n", numberStr, err)
		return
	}

	fmt.Printf("The converted number is: %d\n", num)
}
```

在这个例子中，`-number` 就是一个命令行参数，它的值会被赋值给 `numberStr` 变量，然后 `strconv.Atoi` 可以被用来转换这个字符串。

**使用者易犯错的点：**

1. **未检查错误：** 使用 `strconv.Atoi`、`strconv.ParseInt` 或 `strconv.ParseUint` 后，务必检查返回的 `error` 值。如果没有错误处理，当输入无效字符串时，程序可能会崩溃或产生不可预测的结果。

   ```go
   num, _ := strconv.Atoi(inputString) // 容易出错，忽略了错误
   fmt.Println(num)
   ```

   正确的做法是：

   ```go
   num, err := strconv.Atoi(inputString)
   if err != nil {
       fmt.Println("转换错误:", err)
       // 进行错误处理，例如返回默认值或退出程序
   } else {
       fmt.Println("转换结果:", num)
   }
   ```

2. **进制理解错误：** 当使用 `strconv.ParseInt` 或 `strconv.ParseUint` 时，`base` 参数的含义很重要。如果期望解析特定进制的数字，需要确保 `base` 参数设置正确。如果设置为 0，需要理解其自动判断进制的规则。

   ```go
   // 期望解析二进制，但 base 设置为 10
   num, _ := strconv.ParseInt("1010", 10, 64) // 结果是 1010，而不是二进制的 10
   fmt.Println(num)

   // 正确解析二进制
   num, _ = strconv.ParseInt("1010", 2, 64)
   fmt.Println(num)
   ```

3. **`bitSize` 设置不当：**  `bitSize` 决定了结果可以表示的最大值和最小值。如果输入字符串表示的数字超出了 `bitSize` 限制的范围，会返回 `strconv.ErrRange` 错误。需要根据实际需求选择合适的 `bitSize`。

   ```go
   // 尝试将一个很大的数放入 int8
   num, err := strconv.ParseInt("200", 10, 8)
   fmt.Println(num, err) // 输出 127 strconv.ErrRange (int8 的最大值)
   ```

4. **对 `Atoi` 的误用：** `Atoi` 只能用于十进制字符串到 `int` 的转换。如果需要解析其他进制或需要指定位大小，应该使用 `ParseInt`。

   ```go
   // 尝试用 Atoi 解析十六进制，会失败
   num, err := strconv.Atoi("0xFF")
   fmt.Println(num, err) // 输出 0 strconv.ErrSyntax
   ```

5. **忽略下划线规则：** 当 `base` 为 0 时，下划线可以用作数字分隔符，但其位置必须符合 Go 的语法规则（只能出现在数字之间或进制前缀和数字之间）。不符合规则的下划线会导致解析错误。

   ```go
   _, err := strconv.ParseUint("1__000", 0, 64)
   fmt.Println(err) // 输出 strconv.NumError，ErrSyntax
   ```

### 提示词
```
这是路径为go/src/strconv/atoi.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package strconv

import (
	"errors"
	"internal/stringslite"
)

// lower(c) is a lower-case letter if and only if
// c is either that lower-case letter or the equivalent upper-case letter.
// Instead of writing c == 'x' || c == 'X' one can write lower(c) == 'x'.
// Note that lower of non-letters can produce other non-letters.
func lower(c byte) byte {
	return c | ('x' - 'X')
}

// ErrRange indicates that a value is out of range for the target type.
var ErrRange = errors.New("value out of range")

// ErrSyntax indicates that a value does not have the right syntax for the target type.
var ErrSyntax = errors.New("invalid syntax")

// A NumError records a failed conversion.
type NumError struct {
	Func string // the failing function (ParseBool, ParseInt, ParseUint, ParseFloat, ParseComplex)
	Num  string // the input
	Err  error  // the reason the conversion failed (e.g. ErrRange, ErrSyntax, etc.)
}

func (e *NumError) Error() string {
	return "strconv." + e.Func + ": " + "parsing " + Quote(e.Num) + ": " + e.Err.Error()
}

func (e *NumError) Unwrap() error { return e.Err }

// All ParseXXX functions allow the input string to escape to the error value.
// This hurts strconv.ParseXXX(string(b)) calls where b is []byte since
// the conversion from []byte must allocate a string on the heap.
// If we assume errors are infrequent, then we can avoid escaping the input
// back to the output by copying it first. This allows the compiler to call
// strconv.ParseXXX without a heap allocation for most []byte to string
// conversions, since it can now prove that the string cannot escape Parse.

func syntaxError(fn, str string) *NumError {
	return &NumError{fn, stringslite.Clone(str), ErrSyntax}
}

func rangeError(fn, str string) *NumError {
	return &NumError{fn, stringslite.Clone(str), ErrRange}
}

func baseError(fn, str string, base int) *NumError {
	return &NumError{fn, stringslite.Clone(str), errors.New("invalid base " + Itoa(base))}
}

func bitSizeError(fn, str string, bitSize int) *NumError {
	return &NumError{fn, stringslite.Clone(str), errors.New("invalid bit size " + Itoa(bitSize))}
}

const intSize = 32 << (^uint(0) >> 63)

// IntSize is the size in bits of an int or uint value.
const IntSize = intSize

const maxUint64 = 1<<64 - 1

// ParseUint is like [ParseInt] but for unsigned numbers.
//
// A sign prefix is not permitted.
func ParseUint(s string, base int, bitSize int) (uint64, error) {
	const fnParseUint = "ParseUint"

	if s == "" {
		return 0, syntaxError(fnParseUint, s)
	}

	base0 := base == 0

	s0 := s
	switch {
	case 2 <= base && base <= 36:
		// valid base; nothing to do

	case base == 0:
		// Look for octal, hex prefix.
		base = 10
		if s[0] == '0' {
			switch {
			case len(s) >= 3 && lower(s[1]) == 'b':
				base = 2
				s = s[2:]
			case len(s) >= 3 && lower(s[1]) == 'o':
				base = 8
				s = s[2:]
			case len(s) >= 3 && lower(s[1]) == 'x':
				base = 16
				s = s[2:]
			default:
				base = 8
				s = s[1:]
			}
		}

	default:
		return 0, baseError(fnParseUint, s0, base)
	}

	if bitSize == 0 {
		bitSize = IntSize
	} else if bitSize < 0 || bitSize > 64 {
		return 0, bitSizeError(fnParseUint, s0, bitSize)
	}

	// Cutoff is the smallest number such that cutoff*base > maxUint64.
	// Use compile-time constants for common cases.
	var cutoff uint64
	switch base {
	case 10:
		cutoff = maxUint64/10 + 1
	case 16:
		cutoff = maxUint64/16 + 1
	default:
		cutoff = maxUint64/uint64(base) + 1
	}

	maxVal := uint64(1)<<uint(bitSize) - 1

	underscores := false
	var n uint64
	for _, c := range []byte(s) {
		var d byte
		switch {
		case c == '_' && base0:
			underscores = true
			continue
		case '0' <= c && c <= '9':
			d = c - '0'
		case 'a' <= lower(c) && lower(c) <= 'z':
			d = lower(c) - 'a' + 10
		default:
			return 0, syntaxError(fnParseUint, s0)
		}

		if d >= byte(base) {
			return 0, syntaxError(fnParseUint, s0)
		}

		if n >= cutoff {
			// n*base overflows
			return maxVal, rangeError(fnParseUint, s0)
		}
		n *= uint64(base)

		n1 := n + uint64(d)
		if n1 < n || n1 > maxVal {
			// n+d overflows
			return maxVal, rangeError(fnParseUint, s0)
		}
		n = n1
	}

	if underscores && !underscoreOK(s0) {
		return 0, syntaxError(fnParseUint, s0)
	}

	return n, nil
}

// ParseInt interprets a string s in the given base (0, 2 to 36) and
// bit size (0 to 64) and returns the corresponding value i.
//
// The string may begin with a leading sign: "+" or "-".
//
// If the base argument is 0, the true base is implied by the string's
// prefix following the sign (if present): 2 for "0b", 8 for "0" or "0o",
// 16 for "0x", and 10 otherwise. Also, for argument base 0 only,
// underscore characters are permitted as defined by the Go syntax for
// [integer literals].
//
// The bitSize argument specifies the integer type
// that the result must fit into. Bit sizes 0, 8, 16, 32, and 64
// correspond to int, int8, int16, int32, and int64.
// If bitSize is below 0 or above 64, an error is returned.
//
// The errors that ParseInt returns have concrete type [*NumError]
// and include err.Num = s. If s is empty or contains invalid
// digits, err.Err = [ErrSyntax] and the returned value is 0;
// if the value corresponding to s cannot be represented by a
// signed integer of the given size, err.Err = [ErrRange] and the
// returned value is the maximum magnitude integer of the
// appropriate bitSize and sign.
//
// [integer literals]: https://go.dev/ref/spec#Integer_literals
func ParseInt(s string, base int, bitSize int) (i int64, err error) {
	const fnParseInt = "ParseInt"

	if s == "" {
		return 0, syntaxError(fnParseInt, s)
	}

	// Pick off leading sign.
	s0 := s
	neg := false
	if s[0] == '+' {
		s = s[1:]
	} else if s[0] == '-' {
		neg = true
		s = s[1:]
	}

	// Convert unsigned and check range.
	var un uint64
	un, err = ParseUint(s, base, bitSize)
	if err != nil && err.(*NumError).Err != ErrRange {
		err.(*NumError).Func = fnParseInt
		err.(*NumError).Num = stringslite.Clone(s0)
		return 0, err
	}

	if bitSize == 0 {
		bitSize = IntSize
	}

	cutoff := uint64(1 << uint(bitSize-1))
	if !neg && un >= cutoff {
		return int64(cutoff - 1), rangeError(fnParseInt, s0)
	}
	if neg && un > cutoff {
		return -int64(cutoff), rangeError(fnParseInt, s0)
	}
	n := int64(un)
	if neg {
		n = -n
	}
	return n, nil
}

// Atoi is equivalent to ParseInt(s, 10, 0), converted to type int.
func Atoi(s string) (int, error) {
	const fnAtoi = "Atoi"

	sLen := len(s)
	if intSize == 32 && (0 < sLen && sLen < 10) ||
		intSize == 64 && (0 < sLen && sLen < 19) {
		// Fast path for small integers that fit int type.
		s0 := s
		if s[0] == '-' || s[0] == '+' {
			s = s[1:]
			if len(s) < 1 {
				return 0, syntaxError(fnAtoi, s0)
			}
		}

		n := 0
		for _, ch := range []byte(s) {
			ch -= '0'
			if ch > 9 {
				return 0, syntaxError(fnAtoi, s0)
			}
			n = n*10 + int(ch)
		}
		if s0[0] == '-' {
			n = -n
		}
		return n, nil
	}

	// Slow path for invalid, big, or underscored integers.
	i64, err := ParseInt(s, 10, 0)
	if nerr, ok := err.(*NumError); ok {
		nerr.Func = fnAtoi
	}
	return int(i64), err
}

// underscoreOK reports whether the underscores in s are allowed.
// Checking them in this one function lets all the parsers skip over them simply.
// Underscore must appear only between digits or between a base prefix and a digit.
func underscoreOK(s string) bool {
	// saw tracks the last character (class) we saw:
	// ^ for beginning of number,
	// 0 for a digit or base prefix,
	// _ for an underscore,
	// ! for none of the above.
	saw := '^'
	i := 0

	// Optional sign.
	if len(s) >= 1 && (s[0] == '-' || s[0] == '+') {
		s = s[1:]
	}

	// Optional base prefix.
	hex := false
	if len(s) >= 2 && s[0] == '0' && (lower(s[1]) == 'b' || lower(s[1]) == 'o' || lower(s[1]) == 'x') {
		i = 2
		saw = '0' // base prefix counts as a digit for "underscore as digit separator"
		hex = lower(s[1]) == 'x'
	}

	// Number proper.
	for ; i < len(s); i++ {
		// Digits are always okay.
		if '0' <= s[i] && s[i] <= '9' || hex && 'a' <= lower(s[i]) && lower(s[i]) <= 'f' {
			saw = '0'
			continue
		}
		// Underscore must follow digit.
		if s[i] == '_' {
			if saw != '0' {
				return false
			}
			saw = '_'
			continue
		}
		// Underscore must also be followed by digit.
		if saw == '_' {
			return false
		}
		// Saw non-digit, non-underscore.
		saw = '!'
	}
	return saw != '_'
}
```