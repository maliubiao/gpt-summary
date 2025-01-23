Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The request asks for the functionality of the code, the Go feature it demonstrates, code examples, handling of command-line arguments (if any), and common mistakes. The context is a `_test.go` file within the `strconv` package, strongly suggesting it's demonstrating the usage of functions in the `strconv` package.

2. **Initial Scan and Keyword Identification:**  Quickly scan the code for keywords and function names. Notice the `package strconv_test`, `import "strconv"`, and numerous functions starting with `Example`. The `Example` prefix is a strong indicator of example functions used for documentation and testing in Go. Also, spot the usage of `fmt.Println` and comments like `// Output:`, which confirms these are example functions with expected output.

3. **Categorize the Examples:** Start grouping the `Example` functions based on the `strconv` function they use. This helps organize the analysis:

    * **Append Functions:** `AppendBool`, `AppendFloat`, `AppendInt`, `AppendQuote`, `AppendQuoteRune`, `AppendQuoteRuneToASCII`, `AppendQuoteToASCII`, `AppendUint`. These functions seem to be about appending formatted values to a byte slice.
    * **Format Functions:** `FormatBool`, `FormatFloat`, `FormatInt`, `FormatUint`. These likely format values into strings.
    * **Parse Functions:** `Atoi`, `ParseBool`, `ParseFloat`, `ParseInt`, `ParseUint`. These functions seem to parse strings into different data types.
    * **Quote/Unquote Functions:** `CanBackquote`, `Quote`, `QuoteRune`, `QuoteRuneToASCII`, `QuoteRuneToGraphic`, `QuoteToASCII`, `QuoteToGraphic`, `QuotedPrefix`, `Unquote`, `UnquoteChar`. These deal with quoting and unquoting strings and runes.
    * **Utility Functions:** `IsGraphic`, `IsPrint`, `Itoa`. These appear to be utility functions for checking character properties or simple conversions.
    * **Error Handling:** `NumError`. This demonstrates how to handle errors specifically from the `strconv` package.

4. **Analyze Individual Example Functions:**  For each group, examine the code within the `Example` function:

    * **Identify the `strconv` function being used.**
    * **Determine the input parameters.**
    * **Observe the expected output.**
    * **Infer the functionality of the `strconv` function based on the input and output.**

    *Example for `ExampleAppendBool`:*
        * Function: `strconv.AppendBool(b, true)`
        * Input: A byte slice `b` and a boolean value `true`.
        * Output: `bool:true` (printed after converting the modified byte slice to a string).
        * Inference: `AppendBool` appends the string representation of the boolean to the byte slice.

5. **Synthesize the Functionality:** After analyzing several examples, start summarizing the core functionalities of the `strconv` package as demonstrated:

    * Converting basic data types (bool, int, float) to and from string representations.
    * Formatting numbers in different bases.
    * Quoting and unquoting strings, handling special characters and encodings.
    * Checking properties of characters (graphic, printable).
    * Appending formatted values to byte slices.
    * Handling errors during parsing.

6. **Infer the Go Language Feature:**  The systematic use of `Example` functions with `// Output:` comments directly points to Go's documentation and testing feature. These examples are used by `go test` to verify the functionality and are included in the package's documentation.

7. **Provide Code Examples (Based on Existing Examples):** The provided code *is* the examples. The task is to explain these and perhaps create slightly modified examples if needed for clarity. In this case, the existing examples are quite clear, so simply referring to them and explaining their purpose is sufficient.

8. **Address Command-Line Arguments:** Carefully review the code. There's no explicit handling of command-line arguments using packages like `flag` or `os.Args`. Therefore, the answer should state that command-line arguments are not directly involved in this specific code snippet.

9. **Identify Common Mistakes:**  Think about potential pitfalls when using the `strconv` package:

    * **Incorrect Base for Integer Conversion:**  Using the wrong base (e.g., trying to parse a hexadecimal number with base 10).
    * **Parsing Errors:**  Providing strings that cannot be parsed into the desired type (e.g., "abc" when expecting an integer).
    * **Precision Issues with Floats:** Understanding the limitations of floating-point representation and the potential for slight inaccuracies.
    * **Forgetting Error Handling:** Not checking the returned `error` value from parsing functions.

10. **Structure the Answer:** Organize the findings logically using the prompts provided in the request:

    * **Functionality:** List the general capabilities.
    * **Go Language Feature:** Explain the `Example` function convention.
    * **Code Examples:** Refer to the provided examples and explain their purpose.
    * **Command-Line Arguments:** State that they are not involved.
    * **Common Mistakes:** Provide concrete examples of common errors.

11. **Review and Refine:** Read through the complete answer to ensure accuracy, clarity, and completeness. Make sure the language is precise and easy to understand. For instance, initially, I might have just said "converts strings to numbers."  Refining that to "将字符串转换为各种数值类型，并将数值类型转换为字符串" (converts strings to various numeric types and numeric types to strings) is more accurate.

By following this structured approach, you can effectively analyze and explain the functionality of the given Go code snippet. The key is to break down the problem into smaller, manageable parts and leverage the clues provided in the code itself (like the `Example` prefix and `// Output:` comments).
这段代码是 Go 语言标准库 `strconv` 包的示例测试代码。它主要用来演示 `strconv` 包中各个函数的用法，并作为该包的文档示例。

**功能列举:**

这段代码展示了 `strconv` 包中以下函数的功能：

1. **Append 系列函数 (用于将转换后的值追加到字节切片):**
   - `AppendBool`: 将布尔值追加到字节切片。
   - `AppendFloat`: 将浮点数追加到字节切片。可以指定精度和格式。
   - `AppendInt`: 将有符号整数追加到字节切片。可以指定进制。
   - `AppendUint`: 将无符号整数追加到字节切片。可以指定进制。
   - `AppendQuote`: 将字符串用双引号包裹并转义后追加到字节切片。
   - `AppendQuoteRune`: 将 rune 类型用单引号包裹并转义后追加到字节切片。
   - `AppendQuoteRuneToASCII`: 将 rune 类型用单引号包裹并转义为 ASCII 字符后追加到字节切片。
   - `AppendQuoteToASCII`: 将字符串用双引号包裹并转义为 ASCII 字符后追加到字节切片。

2. **Format 系列函数 (用于将值格式化为字符串):**
   - `FormatBool`: 将布尔值格式化为字符串 "true" 或 "false"。
   - `FormatFloat`: 将浮点数格式化为字符串。可以指定精度和格式。
   - `FormatInt`: 将有符号整数格式化为指定进制的字符串。
   - `FormatUint`: 将无符号整数格式化为指定进制的字符串。

3. **Parse 系列函数 (用于将字符串解析为对应的值):**
   - `Atoi`: 将字符串解析为整数，等价于 `ParseInt(s, 10, 0)`。
   - `ParseBool`: 将字符串解析为布尔值。接受 "1", "t", "T", "true", "TRUE", "True", "0", "f", "F", "false", "FALSE", "False"。
   - `ParseFloat`: 将字符串解析为浮点数。可以指定精度 (32 位或 64 位)。
   - `ParseInt`: 将字符串解析为指定进制和位数的有符号整数。
   - `ParseUint`: 将字符串解析为指定进制和位数的无符号整数。

4. **Quote 和 Unquote 系列函数 (用于处理带引号的字符串):**
   - `CanBackquote`: 判断字符串是否可以使用反引号（``）括起来而不需转义。
   - `Quote`: 将字符串用双引号包裹并转义特殊字符。
   - `QuoteRune`: 将 rune 类型用单引号包裹并转义特殊字符。
   - `QuoteRuneToASCII`: 将 rune 类型用单引号包裹并转义为 ASCII 字符表示。
   - `QuoteRuneToGraphic`: 将 rune 类型用单引号包裹，如果是非图形字符则转义。
   - `QuoteToASCII`: 将字符串用双引号包裹并转义为 ASCII 字符表示。
   - `QuoteToGraphic`: 将字符串用双引号包裹，如果包含非图形字符则转义。
   - `QuotedPrefix`: 检查字符串是否以单引号、双引号或反引号开始，并返回引用的部分。
   - `Unquote`: 移除字符串的首尾引号（单引号、双引号或反引号），并对其中的转义字符进行处理。
   - `UnquoteChar`: 解析带引号的字符串的第一个字符，返回字符的值、是否是多字节字符以及剩余部分。

5. **其他函数:**
   - `IsGraphic`: 判断一个 rune 是否是 Unicode 定义的图形字符。
   - `IsPrint`: 判断一个 rune 是否是可打印字符。
   - `Itoa`: 将整数转换为字符串，等价于 `FormatInt(i, 10)`。

6. **错误处理:**
   - `NumError`:  演示了 `Parse` 系列函数在解析失败时返回的错误类型，包含了函数名、尝试解析的字符串和具体的错误信息。

**Go 语言功能的实现 (以 `ParseInt` 为例):**

`ParseInt` 函数实现了将字符串解析为有符号整数的功能。它可以处理不同进制的数字。

```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	// 假设输入的是一个表示十进制数字的字符串
	inputDecimal := "12345"
	// 将字符串解析为 64 位有符号整数，进制为 10
	decimalValue, err := strconv.ParseInt(inputDecimal, 10, 64)
	if err != nil {
		fmt.Println("解析十进制失败:", err)
	} else {
		fmt.Printf("输入的十进制字符串: %s, 解析后的整数: %d (类型: %T)\n", inputDecimal, decimalValue, decimalValue)
	}

	// 假设输入的是一个表示十六进制数字的字符串
	inputHex := "1A2B"
	// 将字符串解析为 32 位有符号整数，进制为 16
	hexValue, err := strconv.ParseInt(inputHex, 16, 32)
	if err != nil {
		fmt.Println("解析十六进制失败:", err)
	} else {
		fmt.Printf("输入的十六进制字符串: %s, 解析后的整数: %d (类型: %T)\n", inputHex, hexValue, hexValue)
	}

	// 假设输入的是一个超出 int32 范围的十六进制数字
	inputHexOutOfRange := "FFFFFFFFFFFFFFFF"
	// 尝试解析为 32 位有符号整数，会报错
	outOfRangeValue, err := strconv.ParseInt(inputHexOutOfRange, 16, 32)
	if err != nil {
		fmt.Println("解析超出范围的十六进制失败:", err)
	} else {
		fmt.Printf("输入的超出范围的十六进制字符串: %s, 解析后的整数: %d (类型: %T)\n", inputHexOutOfRange, outOfRangeValue, outOfRangeValue)
	}

	// 假设输入的是一个无效的十六进制字符串
	invalidHex := "1G2B"
	invalidValue, err := strconv.ParseInt(invalidHex, 16, 32)
	if err != nil {
		fmt.Println("解析无效的十六进制失败:", err)
	} else {
		fmt.Printf("输入的无效十六进制字符串: %s, 解析后的整数: %d (类型: %T)\n", invalidHex, invalidValue, invalidValue)
	}
}

// 假设的输出:
// 输入的十进制字符串: 12345, 解析后的整数: 12345 (类型: int64)
// 输入的十六进制字符串: 1A2B, 解析后的整数: 6707 (类型: int64)
// 解析超出范围的十六进制失败: strconv.ParseInt: parsing "FFFFFFFFFFFFFFFF": value out of range
// 解析无效的十六进制失败: strconv.ParseInt: parsing "1G2B": invalid syntax
```

**假设的输入与输出:**

在上面的 `ParseInt` 例子中，我们假设了以下输入和预期输出：

- **输入:** "12345", 进制 10, 位数 64  **输出:** 12345 (int64)
- **输入:** "1A2B", 进制 16, 位数 32  **输出:** 6707 (int64)
- **输入:** "FFFFFFFFFFFFFFFF", 进制 16, 位数 32 **输出:** 错误信息 "strconv.ParseInt: parsing "FFFFFFFFFFFFFFFF": value out of range"
- **输入:** "1G2B", 进制 16, 位数 32 **输出:** 错误信息 "strconv.ParseInt: parsing "1G2B": invalid syntax"

**命令行参数处理:**

这段代码本身没有直接处理命令行参数。它主要是作为 `strconv` 包的示例和测试用例。`strconv` 包的函数本身也不直接涉及命令行参数的处理。如果你想在你的 Go 程序中使用 `strconv` 包的函数来处理从命令行接收到的字符串参数，你需要使用 `os` 包来获取命令行参数，然后将这些参数传递给 `strconv` 包的函数进行转换。

例如：

```go
package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("请提供一个需要转换的数字作为命令行参数")
		return
	}

	numberStr := os.Args[1]

	// 尝试将命令行参数解析为整数
	num, err := strconv.Atoi(numberStr)
	if err != nil {
		fmt.Printf("无法将 '%s' 转换为整数: %v\n", numberStr, err)
		return
	}

	fmt.Printf("命令行参数 '%s' 转换为整数: %d\n", numberStr, num)
}
```

在这个例子中，`os.Args[1]` 获取第一个命令行参数，然后使用 `strconv.Atoi` 将其转换为整数。

**使用者易犯错的点:**

1. **进制错误:** 在使用 `ParseInt` 或 `ParseUint` 时，指定的进制与字符串实际的进制不符，导致解析错误。
   ```go
   package main

   import (
       "fmt"
       "strconv"
   )

   func main() {
       // 尝试将十六进制字符串用十进制解析
       val, err := strconv.ParseInt("FF", 10, 64)
       if err != nil {
           fmt.Println("错误:", err) // 输出: 错误: strconv.ParseInt: parsing "FF": invalid syntax
       } else {
           fmt.Println(val)
       }
   }
   ```

2. **超出范围的数值:** 尝试将超出指定位数范围的字符串解析为整数，会导致溢出错误。
   ```go
   package main

   import (
       "fmt"
       "strconv"
   )

   func main() {
       // 尝试将一个很大的数解析为 int8 (范围 -128 到 127)
       val, err := strconv.ParseInt("200", 10, 8)
       if err != nil {
           fmt.Println("错误:", err) // 输出: 错误: strconv.ParseInt: parsing "200": value out of range
       } else {
           fmt.Println(val)
       }
   }
   ```

3. **未处理错误:**  `Parse` 系列函数在解析失败时会返回错误，如果不对错误进行处理，可能会导致程序崩溃或产生意想不到的结果。
   ```go
   package main

   import (
       "fmt"
       "strconv"
   )

   func main() {
       // 忘记检查错误
       val, _ := strconv.Atoi("abc")
       fmt.Println(val) // 输出: 0 (默认值，但可能不是期望的结果)
   }
   ```

4. **浮点数精度问题:** 在使用 `ParseFloat` 或 `FormatFloat` 时，需要注意浮点数的精度问题。浮点数的表示存在一定的误差。

5. **不理解 Quote 和 Unquote 的作用:**  错误地使用 `Quote` 和 `Unquote` 函数，例如尝试 `Unquote` 一个没有被引号包裹的字符串，或者期望 `Quote` 函数能处理所有类型的转义。
```go
package main

import (
	"fmt"
	"strconv"
)

func main() {
	str := "hello"
	unquoted, err := strconv.Unquote(str)
	if err != nil {
		fmt.Println("Unquote 错误:", err) // 输出: Unquote 错误: invalid syntax
	} else {
		fmt.Println(unquoted)
	}
}
```

总而言之，这段代码通过一系列的示例展示了 `strconv` 包提供的各种字符串和基本数据类型之间的转换和格式化功能，是学习和理解该包的很好的参考资料。

### 提示词
```
这是路径为go/src/strconv/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package strconv_test

import (
	"fmt"
	"log"
	"strconv"
)

func ExampleAppendBool() {
	b := []byte("bool:")
	b = strconv.AppendBool(b, true)
	fmt.Println(string(b))

	// Output:
	// bool:true
}

func ExampleAppendFloat() {
	b32 := []byte("float32:")
	b32 = strconv.AppendFloat(b32, 3.1415926535, 'E', -1, 32)
	fmt.Println(string(b32))

	b64 := []byte("float64:")
	b64 = strconv.AppendFloat(b64, 3.1415926535, 'E', -1, 64)
	fmt.Println(string(b64))

	// Output:
	// float32:3.1415927E+00
	// float64:3.1415926535E+00
}

func ExampleAppendInt() {
	b10 := []byte("int (base 10):")
	b10 = strconv.AppendInt(b10, -42, 10)
	fmt.Println(string(b10))

	b16 := []byte("int (base 16):")
	b16 = strconv.AppendInt(b16, -42, 16)
	fmt.Println(string(b16))

	// Output:
	// int (base 10):-42
	// int (base 16):-2a
}

func ExampleAppendQuote() {
	b := []byte("quote:")
	b = strconv.AppendQuote(b, `"Fran & Freddie's Diner"`)
	fmt.Println(string(b))

	// Output:
	// quote:"\"Fran & Freddie's Diner\""
}

func ExampleAppendQuoteRune() {
	b := []byte("rune:")
	b = strconv.AppendQuoteRune(b, '☺')
	fmt.Println(string(b))

	// Output:
	// rune:'☺'
}

func ExampleAppendQuoteRuneToASCII() {
	b := []byte("rune (ascii):")
	b = strconv.AppendQuoteRuneToASCII(b, '☺')
	fmt.Println(string(b))

	// Output:
	// rune (ascii):'\u263a'
}

func ExampleAppendQuoteToASCII() {
	b := []byte("quote (ascii):")
	b = strconv.AppendQuoteToASCII(b, `"Fran & Freddie's Diner"`)
	fmt.Println(string(b))

	// Output:
	// quote (ascii):"\"Fran & Freddie's Diner\""
}

func ExampleAppendUint() {
	b10 := []byte("uint (base 10):")
	b10 = strconv.AppendUint(b10, 42, 10)
	fmt.Println(string(b10))

	b16 := []byte("uint (base 16):")
	b16 = strconv.AppendUint(b16, 42, 16)
	fmt.Println(string(b16))

	// Output:
	// uint (base 10):42
	// uint (base 16):2a
}

func ExampleAtoi() {
	v := "10"
	if s, err := strconv.Atoi(v); err == nil {
		fmt.Printf("%T, %v", s, s)
	}

	// Output:
	// int, 10
}

func ExampleCanBackquote() {
	fmt.Println(strconv.CanBackquote("Fran & Freddie's Diner ☺"))
	fmt.Println(strconv.CanBackquote("`can't backquote this`"))

	// Output:
	// true
	// false
}

func ExampleFormatBool() {
	v := true
	s := strconv.FormatBool(v)
	fmt.Printf("%T, %v\n", s, s)

	// Output:
	// string, true
}

func ExampleFormatFloat() {
	v := 3.1415926535

	s32 := strconv.FormatFloat(v, 'E', -1, 32)
	fmt.Printf("%T, %v\n", s32, s32)

	s64 := strconv.FormatFloat(v, 'E', -1, 64)
	fmt.Printf("%T, %v\n", s64, s64)

	// fmt.Println uses these arguments to print floats
	fmt64 := strconv.FormatFloat(v, 'g', -1, 64)
	fmt.Printf("%T, %v\n", fmt64, fmt64)

	// Output:
	// string, 3.1415927E+00
	// string, 3.1415926535E+00
	// string, 3.1415926535
}

func ExampleFormatInt() {
	v := int64(-42)

	s10 := strconv.FormatInt(v, 10)
	fmt.Printf("%T, %v\n", s10, s10)

	s16 := strconv.FormatInt(v, 16)
	fmt.Printf("%T, %v\n", s16, s16)

	// Output:
	// string, -42
	// string, -2a
}

func ExampleFormatUint() {
	v := uint64(42)

	s10 := strconv.FormatUint(v, 10)
	fmt.Printf("%T, %v\n", s10, s10)

	s16 := strconv.FormatUint(v, 16)
	fmt.Printf("%T, %v\n", s16, s16)

	// Output:
	// string, 42
	// string, 2a
}

func ExampleIsGraphic() {
	shamrock := strconv.IsGraphic('☘')
	fmt.Println(shamrock)

	a := strconv.IsGraphic('a')
	fmt.Println(a)

	bel := strconv.IsGraphic('\007')
	fmt.Println(bel)

	// Output:
	// true
	// true
	// false
}

func ExampleIsPrint() {
	c := strconv.IsPrint('\u263a')
	fmt.Println(c)

	bel := strconv.IsPrint('\007')
	fmt.Println(bel)

	// Output:
	// true
	// false
}

func ExampleItoa() {
	i := 10
	s := strconv.Itoa(i)
	fmt.Printf("%T, %v\n", s, s)

	// Output:
	// string, 10
}

func ExampleParseBool() {
	v := "true"
	if s, err := strconv.ParseBool(v); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}

	// Output:
	// bool, true
}

func ExampleParseFloat() {
	v := "3.1415926535"
	if s, err := strconv.ParseFloat(v, 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseFloat(v, 64); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseFloat("NaN", 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	// ParseFloat is case insensitive
	if s, err := strconv.ParseFloat("nan", 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseFloat("inf", 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseFloat("+Inf", 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseFloat("-Inf", 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseFloat("-0", 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseFloat("+0", 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}

	// Output:
	// float64, 3.1415927410125732
	// float64, 3.1415926535
	// float64, NaN
	// float64, NaN
	// float64, +Inf
	// float64, +Inf
	// float64, -Inf
	// float64, -0
	// float64, 0
}

func ExampleParseInt() {
	v32 := "-354634382"
	if s, err := strconv.ParseInt(v32, 10, 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseInt(v32, 16, 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}

	v64 := "-3546343826724305832"
	if s, err := strconv.ParseInt(v64, 10, 64); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseInt(v64, 16, 64); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}

	// Output:
	// int64, -354634382
	// int64, -3546343826724305832
}

func ExampleParseUint() {
	v := "42"
	if s, err := strconv.ParseUint(v, 10, 32); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}
	if s, err := strconv.ParseUint(v, 10, 64); err == nil {
		fmt.Printf("%T, %v\n", s, s)
	}

	// Output:
	// uint64, 42
	// uint64, 42
}

func ExampleQuote() {
	// This string literal contains a tab character.
	s := strconv.Quote(`"Fran & Freddie's Diner	☺"`)
	fmt.Println(s)

	// Output:
	// "\"Fran & Freddie's Diner\t☺\""
}

func ExampleQuoteRune() {
	s := strconv.QuoteRune('☺')
	fmt.Println(s)

	// Output:
	// '☺'
}

func ExampleQuoteRuneToASCII() {
	s := strconv.QuoteRuneToASCII('☺')
	fmt.Println(s)

	// Output:
	// '\u263a'
}

func ExampleQuoteRuneToGraphic() {
	s := strconv.QuoteRuneToGraphic('☺')
	fmt.Println(s)

	s = strconv.QuoteRuneToGraphic('\u263a')
	fmt.Println(s)

	s = strconv.QuoteRuneToGraphic('\u000a')
	fmt.Println(s)

	s = strconv.QuoteRuneToGraphic('	') // tab character
	fmt.Println(s)

	// Output:
	// '☺'
	// '☺'
	// '\n'
	// '\t'
}

func ExampleQuoteToASCII() {
	// This string literal contains a tab character.
	s := strconv.QuoteToASCII(`"Fran & Freddie's Diner	☺"`)
	fmt.Println(s)

	// Output:
	// "\"Fran & Freddie's Diner\t\u263a\""
}

func ExampleQuoteToGraphic() {
	s := strconv.QuoteToGraphic("☺")
	fmt.Println(s)

	// This string literal contains a tab character.
	s = strconv.QuoteToGraphic("This is a \u263a	\u000a")
	fmt.Println(s)

	s = strconv.QuoteToGraphic(`" This is a ☺ \n "`)
	fmt.Println(s)

	// Output:
	// "☺"
	// "This is a ☺\t\n"
	// "\" This is a ☺ \\n \""
}

func ExampleQuotedPrefix() {
	s, err := strconv.QuotedPrefix("not a quoted string")
	fmt.Printf("%q, %v\n", s, err)
	s, err = strconv.QuotedPrefix("\"double-quoted string\" with trailing text")
	fmt.Printf("%q, %v\n", s, err)
	s, err = strconv.QuotedPrefix("`or backquoted` with more trailing text")
	fmt.Printf("%q, %v\n", s, err)
	s, err = strconv.QuotedPrefix("'\u263a' is also okay")
	fmt.Printf("%q, %v\n", s, err)

	// Output:
	// "", invalid syntax
	// "\"double-quoted string\"", <nil>
	// "`or backquoted`", <nil>
	// "'☺'", <nil>
}

func ExampleUnquote() {
	s, err := strconv.Unquote("You can't unquote a string without quotes")
	fmt.Printf("%q, %v\n", s, err)
	s, err = strconv.Unquote("\"The string must be either double-quoted\"")
	fmt.Printf("%q, %v\n", s, err)
	s, err = strconv.Unquote("`or backquoted.`")
	fmt.Printf("%q, %v\n", s, err)
	s, err = strconv.Unquote("'\u263a'") // single character only allowed in single quotes
	fmt.Printf("%q, %v\n", s, err)
	s, err = strconv.Unquote("'\u2639\u2639'")
	fmt.Printf("%q, %v\n", s, err)

	// Output:
	// "", invalid syntax
	// "The string must be either double-quoted", <nil>
	// "or backquoted.", <nil>
	// "☺", <nil>
	// "", invalid syntax
}

func ExampleUnquoteChar() {
	v, mb, t, err := strconv.UnquoteChar(`\"Fran & Freddie's Diner\"`, '"')
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("value:", string(v))
	fmt.Println("multibyte:", mb)
	fmt.Println("tail:", t)

	// Output:
	// value: "
	// multibyte: false
	// tail: Fran & Freddie's Diner\"
}

func ExampleNumError() {
	str := "Not a number"
	if _, err := strconv.ParseFloat(str, 64); err != nil {
		e := err.(*strconv.NumError)
		fmt.Println("Func:", e.Func)
		fmt.Println("Num:", e.Num)
		fmt.Println("Err:", e.Err)
		fmt.Println(err)
	}

	// Output:
	// Func: ParseFloat
	// Num: Not a number
	// Err: invalid syntax
	// strconv.ParseFloat: parsing "Not a number": invalid syntax
}
```