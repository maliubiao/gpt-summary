Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - The Goal:**

The request asks for an analysis of a Go test file (`strconv_test.go`) within the `archive/tar` package. The key is to understand *what* functionality this test file is verifying.

**2. Deconstructing the Request:**

The prompt has several specific instructions:

* **List the functions:** Identify the test functions within the file.
* **Infer Go feature:** Based on the function names and their internal logic, deduce which Go language feature is being tested.
* **Provide Go code example:**  Illustrate the inferred feature's usage with a practical code snippet.
* **Include input/output for code examples:** Show concrete examples of how the feature works.
* **Address command-line arguments (if applicable):** Determine if the tested functionality involves command-line arguments.
* **Highlight potential pitfalls:** Point out common mistakes users might make.
* **Answer in Chinese.**

**3. Analyzing the Code - Function by Function:**

The core of the analysis involves examining each test function:

* **`TestFitsInBase256(t *testing.T)`:**
    * **Keywords:** `Base256`, `fitsIn`.
    * **Logic:** It iterates through test cases (`vectors`) with `in` (an integer), `width`, and `ok` (a boolean). It calls `fitsInBase256(v.width, v.in)` and compares the result to `v.ok`.
    * **Inference:** This function likely tests whether a given integer can be represented within a specified number of bytes using a base-256 encoding. This is relevant for storing numerical values compactly in a binary format.

* **`TestParseNumeric(t *testing.T)`:**
    * **Keywords:** `ParseNumeric`, `base-256`, `octal`.
    * **Logic:** Tests parsing of strings into `int64`. It includes cases for both base-256 (binary) and base-8 (octal) encoded strings. It uses a `parser` struct (though its definition isn't in the snippet).
    * **Inference:**  This tests the functionality of converting string representations of numbers (in potentially different bases) into integer values. This is crucial for reading numerical data from a tar archive.

* **`TestFormatNumeric(t *testing.T)`:**
    * **Keywords:** `FormatNumeric`, `base-8`, `base-256`.
    * **Logic:** Tests the reverse of `TestParseNumeric`: converting `int64` values into their string representations in base-8 and base-256. It uses a `formatter` struct (again, definition missing).
    * **Inference:** This tests the functionality of converting integer values into string representations suitable for writing to a tar archive.

* **`TestFitsInOctal(t *testing.T)`:**
    * **Keywords:** `Octal`, `fitsIn`.
    * **Logic:**  Similar to `TestFitsInBase256`, but specifically for base-8 (octal) representation.
    * **Inference:** This checks if an integer can be represented within a certain width using octal encoding. Octal is a traditional encoding used in tar headers.

* **`TestParsePAXTime(t *testing.T)`:**
    * **Keywords:** `PAXTime`, `time.Time`.
    * **Logic:** Tests parsing of strings representing timestamps (including fractional seconds) into Go's `time.Time` type.
    * **Inference:** This is about handling timestamps stored in the PAX extended header format of tar archives.

* **`TestFormatPAXTime(t *testing.T)`:**
    * **Keywords:** `PAXTime`.
    * **Logic:** Tests the formatting of `time.Time` values back into PAX timestamp strings.
    * **Inference:**  This is the reverse of `TestParsePAXTime`, for writing timestamps in the PAX format.

* **`TestParsePAXRecord(t *testing.T)`:**
    * **Keywords:** `PAXRecord`.
    * **Logic:** Tests parsing of key-value pairs from PAX extended headers. It looks for the length prefix, the key, the value, and any remaining data.
    * **Inference:** This focuses on processing the structure of PAX extended header records.

* **`TestFormatPAXRecord(t *testing.T)`:**
    * **Keywords:** `PAXRecord`.
    * **Logic:** Tests formatting key-value pairs into the PAX record format (length prefix, key, '=', value, '\n').
    * **Inference:** This is the process of creating PAX extended header records.

**4. Synthesizing the Findings and Addressing the Request:**

After analyzing each function, the next step is to synthesize the information and address each point in the original request:

* **的功能:** Summarize the purpose of each test function in plain language.
* **Go 语言功能推断:**  Identify the broader Go language features being tested (string conversion, time handling).
* **Go 代码举例:**  Create illustrative Go code examples for parsing and formatting numeric values and PAX timestamps. This requires making reasonable assumptions about the underlying implementation since the relevant non-test code is missing.
* **假设输入与输出:**  For the code examples, provide specific input values and the expected output.
* **命令行参数:** Determine that this specific test file doesn't directly involve command-line arguments.
* **易犯错的点:** Think about common mistakes users might make when dealing with numeric and time conversions (e.g., incorrect formats, handling potential errors).
* **中文回答:** Translate all the findings into clear and concise Chinese.

**5. Refinement and Review:**

Finally, review the generated answer for clarity, accuracy, and completeness. Ensure that all aspects of the request have been addressed in Chinese. For instance, double-check the Go code examples for correctness and the assumptions made during inference.

This systematic approach allows for a thorough understanding of the test file's purpose and its connection to the underlying Go language features. The function-by-function analysis combined with synthesizing the findings ensures that all parts of the original request are addressed accurately.
好的，让我们来分析一下 `go/src/archive/tar/strconv_test.go` 这个 Go 语言测试文件片段的功能。

**文件功能概览**

这个文件 (`strconv_test.go`) 包含了针对 `archive/tar` 包中与字符串转换相关的函数的测试。它的主要目的是验证在处理 tar 归档文件时，各种数值类型（如整数、时间）与字符串之间的转换是否正确。

**详细功能点**

1. **`TestFitsInBase256(t *testing.T)`:**
   - **功能:**  测试 `fitsInBase256` 函数。该函数用于判断一个给定的整数是否能用指定宽度的字节数以 Base256 编码表示。Base256 是一种紧凑的二进制编码方式，用于在 tar 文件头中存储数值。
   - **推断的 Go 语言功能:**  整数到 Base256 编码的转换。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "fmt"
         "archive/tar"
     )

     func main() {
         // 假设 fitsInBase256 是 archive/tar 包内部的未导出函数
         // 这里为了演示目的，我们假设它存在
         fits := tar.FitsInBase256(8, 127)
         fmt.Println(fits) // 输出: true

         fits = tar.FitsInBase256(8, 1 << 56)
         fmt.Println(fits) // 输出: false
     }
     ```
   - **假设输入与输出:**
     - 输入: `width = 8`, `in = 127`  => 输出: `true` (127 可以用 8 个字节的 Base256 表示)
     - 输入: `width = 8`, `in = 72057594037927936` (2的56次方) => 输出: `false` (需要超过 8 个字节)

2. **`TestParseNumeric(t *testing.T)`:**
   - **功能:** 测试 `parseNumeric` 函数。该函数用于将 tar 文件头中以特定格式编码的数字字符串（可以是 Base256 或八进制）解析为 `int64` 类型的整数。
   - **推断的 Go 语言功能:** 将 Base256 或八进制字符串转换为整数。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "fmt"
         "archive/tar"
     )

     func main() {
         // 假设 parseNumeric 是 archive/tar 包内部的未导出函数
         // 这里为了演示目的，我们假设它存在
         var p tar.parser // 假设存在 parser 结构体
         val := p.parseNumeric([]byte("\x80\x7f\xff\xff\xff\xff\xff\xff\xff")) // Base256 编码的 MaxInt64
         fmt.Println(val) // 输出: 9223372036854775807

         val = p.parseNumeric([]byte("0000777\x00")) // 八进制编码的 511
         fmt.Println(val) // 输出: 511
     }
     ```
   - **假设输入与输出:**
     - 输入: `in = "\x80\x7f\xff\xff\xff\xff\xff\xff\xff"` (Base256) => 输出: `9223372036854775807` (math.MaxInt64)
     - 输入: `in = "0000777\x00"` (八进制) => 输出: `511`

3. **`TestFormatNumeric(t *testing.T)`:**
   - **功能:** 测试 `formatNumeric` 函数。该函数用于将 `int64` 类型的整数格式化为 tar 文件头中需要的特定格式的字符串（可以是 Base256 或八进制）。
   - **推断的 Go 语言功能:** 将整数转换为 Base256 或八进制字符串。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "fmt"
         "archive/tar"
     )

     func main() {
         // 假设 formatNumeric 是 archive/tar 包内部的未导出函数
         // 这里为了演示目的，我们假设它存在
         var f tar.formatter // 假设存在 formatter 结构体
         buf := make([]byte, 9) // 预分配足够的空间
         f.formatNumeric(buf, 511)
         fmt.Printf("%q\n", string(buf)) // 输出: "777\x00\x00\x00\x00\x00\x00" (八进制)

         buf = make([]byte, 9)
         f.formatNumeric(buf, 9223372036854775807)
         fmt.Printf("%q\n", string(buf)) // 输出: "\x80\x7f\xff\xff\xff\xff\xff\xff\xff" (Base256)
     }
     ```
   - **假设输入与输出:**
     - 输入: `in = 511`, `目标 buffer 长度 = 9` => 输出:  `"777\x00\x00\x00\x00\x00\x00"` (八进制)
     - 输入: `in = 9223372036854775807`, `目标 buffer 长度 = 9` => 输出: `"\x80\x7f\xff\xff\xff\xff\xff\xff\xff"` (Base256)

4. **`TestFitsInOctal(t *testing.T)`:**
   - **功能:** 测试 `fitsInOctal` 函数。该函数用于判断一个给定的整数是否能用指定宽度的字节数以八进制字符串表示，并包含一个空字符终止符。
   - **推断的 Go 语言功能:** 判断整数是否能以特定长度的八进制字符串表示。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "fmt"
         "archive/tar"
     )

     func main() {
         // 假设 fitsInOctal 是 archive/tar 包内部的未导出函数
         // 这里为了演示目的，我们假设它存在
         fits := tar.FitsInOctal(8, 511)
         fmt.Println(fits) // 输出: true

         fits = tar.FitsInOctal(4, 4096) // 八进制 10000，需要 5 位
         fmt.Println(fits) // 输出: false
     }
     ```
   - **假设输入与输出:**
     - 输入: `width = 8`, `input = 511` => 输出: `true` (八进制 "00000777")
     - 输入: `width = 4`, `input = 4096` => 输出: `false` (八进制 "10000")

5. **`TestParsePAXTime(t *testing.T)`:**
   - **功能:** 测试 `parsePAXTime` 函数。该函数用于解析 PAX 扩展头中存储的时间戳字符串，该字符串可以是浮点数形式，包含秒和纳秒。
   - **推断的 Go 语言功能:** 将 PAX 格式的时间字符串转换为 `time.Time` 类型。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "fmt"
         "archive/tar"
         "time"
     )

     func main() {
         ts, err := tar.ParsePAXTime("1350244992.023960108")
         if err != nil {
             fmt.Println(err)
             return
         }
         fmt.Println(ts) // 输出: 2012-10-15 04:03:12.023960108 +0000 UTC
     }
     ```
   - **假设输入与输出:**
     - 输入: `in = "1350244992.023960108"` => 输出:  对应的 `time.Time` 对象，表示 `2012-10-15 04:03:12.023960108 +0000 UTC`

6. **`TestFormatPAXTime(t *testing.T)`:**
   - **功能:** 测试 `formatPAXTime` 函数。该函数用于将 `time.Time` 类型的时间格式化为 PAX 扩展头所需的字符串格式。
   - **推断的 Go 语言功能:** 将 `time.Time` 类型转换为 PAX 格式的时间字符串。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "fmt"
         "archive/tar"
         "time"
     )

     func main() {
         t := time.Unix(1350244992, 23960108)
         paxTime := tar.FormatPAXTime(t)
         fmt.Println(paxTime) // 输出: 1350244992.023960108
     }
     ```
   - **假设输入与输出:**
     - 输入: `sec = 1350244992`, `nsec = 23960108` (对应 `2012-10-15 04:03:12.023960108 +0000 UTC`) => 输出: `"1350244992.023960108"`

7. **`TestParsePAXRecord(t *testing.T)`:**
   - **功能:** 测试 `parsePAXRecord` 函数。该函数用于解析 PAX 扩展头中的单个记录，该记录包含长度、键和值。
   - **推断的 Go 语言功能:** 解析 PAX 扩展头记录的结构。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "fmt"
         "archive/tar"
     )

     func main() {
         key, val, res, err := tar.ParsePAXRecord("19 path=/etc/hosts\n")
         if err != nil {
             fmt.Println(err)
             return
         }
         fmt.Printf("Key: %s, Value: %s, Residual: %s\n", key, val, res)
         // 输出: Key: path, Value: /etc/hosts, Residual:
     }
     ```
   - **假设输入与输出:**
     - 输入: `in = "19 path=/etc/hosts\n"` => 输出: `key = "path"`, `val = "/etc/hosts"`, `res = ""`

8. **`TestFormatPAXRecord(t *testing.T)`:**
   - **功能:** 测试 `formatPAXRecord` 函数。该函数用于将键值对格式化为 PAX 扩展头记录的字符串形式。
   - **推断的 Go 语言功能:** 格式化 PAX 扩展头记录。
   - **Go 代码示例:**
     ```go
     package main

     import (
         "fmt"
         "archive/tar"
     )

     func main() {
         record, err := tar.FormatPAXRecord("path", "/very/long/path/name")
         if err != nil {
             fmt.Println(err)
             return
         }
         fmt.Println(record) // 输出: 25 path=/very/long/path/name\n
     }
     ```
   - **假设输入与输出:**
     - 输入: `inKey = "path"`, `inVal = "/very/long/path/name"` => 输出: `"25 path=/very/long/path/name\n"`

**命令行参数处理**

这个测试文件本身不涉及命令行参数的处理。它主要关注的是内部函数的逻辑正确性。`archive/tar` 包的使用者通常不会直接调用这些 `strconv_test.go` 中测试的底层转换函数。

**使用者易犯错的点**

1. **Base256 编码的理解:**  用户可能不清楚 Base256 编码的细节，例如它是一种二进制编码，而不是简单的文本表示。错误地假设数值可以用普通的字符串表示可能会导致问题。

2. **八进制字符串的格式:**  在 tar 文件头中，数字有时以八进制字符串形式存储，并以空字符 `\0` 结尾。用户在手动构造或解析 tar 文件头时，可能会忘记处理空字符，或者错误地将非八进制字符包含在字符串中。

   ```go
   // 错误示例：忘记添加空字符
   octalString := fmt.Sprintf("%o", 511) // 结果是 "777" 而不是 "777\x00"

   // 错误示例：包含非八进制字符
   invalidOctal := "01238" // 8 不是八进制数字
   ```

3. **PAX 时间戳的精度:** PAX 时间戳支持纳秒级的精度。用户在处理时间时，可能会丢失精度或使用不正确的格式。

   ```go
   // 错误示例：使用 time.Format 格式化 PAX 时间
   t := time.Now()
   formatted := t.Format("2006-01-02 15:04:05.999999999") // 这不是 PAX 格式
   ```

4. **PAX 记录的长度前缀:**  PAX 扩展头记录以一个表示记录总长度的十进制数字开头。用户在构造 PAX 记录时，需要正确计算并添加这个长度前缀，并且以换行符 `\n` 结尾。

   ```go
   // 错误示例：长度前缀计算错误
   key := "filename"
   value := "very_long_filename.txt"
   record := fmt.Sprintf("%d %s=%s", len(key)+len(value)+2, key, value) // 缺少换行符和等号的长度
   ```

**总结**

`go/src/archive/tar/strconv_test.go` 文件专注于测试 `archive/tar` 包中用于在不同数值和字符串表示之间进行转换的关键函数。这些转换对于正确读写 tar 归档文件的元数据至关重要。理解这些转换的细节可以帮助用户避免在使用 `archive/tar` 包时的一些常见错误。

### 提示词
```
这是路径为go/src/archive/tar/strconv_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tar

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestFitsInBase256(t *testing.T) {
	vectors := []struct {
		in    int64
		width int
		ok    bool
	}{
		{+1, 8, true},
		{0, 8, true},
		{-1, 8, true},
		{1 << 56, 8, false},
		{(1 << 56) - 1, 8, true},
		{-1 << 56, 8, true},
		{(-1 << 56) - 1, 8, false},
		{121654, 8, true},
		{-9849849, 8, true},
		{math.MaxInt64, 9, true},
		{0, 9, true},
		{math.MinInt64, 9, true},
		{math.MaxInt64, 12, true},
		{0, 12, true},
		{math.MinInt64, 12, true},
	}

	for _, v := range vectors {
		ok := fitsInBase256(v.width, v.in)
		if ok != v.ok {
			t.Errorf("fitsInBase256(%d, %d): got %v, want %v", v.in, v.width, ok, v.ok)
		}
	}
}

func TestParseNumeric(t *testing.T) {
	vectors := []struct {
		in   string
		want int64
		ok   bool
	}{
		// Test base-256 (binary) encoded values.
		{"", 0, true},
		{"\x80", 0, true},
		{"\x80\x00", 0, true},
		{"\x80\x00\x00", 0, true},
		{"\xbf", (1 << 6) - 1, true},
		{"\xbf\xff", (1 << 14) - 1, true},
		{"\xbf\xff\xff", (1 << 22) - 1, true},
		{"\xff", -1, true},
		{"\xff\xff", -1, true},
		{"\xff\xff\xff", -1, true},
		{"\xc0", -1 * (1 << 6), true},
		{"\xc0\x00", -1 * (1 << 14), true},
		{"\xc0\x00\x00", -1 * (1 << 22), true},
		{"\x87\x76\xa2\x22\xeb\x8a\x72\x61", 537795476381659745, true},
		{"\x80\x00\x00\x00\x07\x76\xa2\x22\xeb\x8a\x72\x61", 537795476381659745, true},
		{"\xf7\x76\xa2\x22\xeb\x8a\x72\x61", -615126028225187231, true},
		{"\xff\xff\xff\xff\xf7\x76\xa2\x22\xeb\x8a\x72\x61", -615126028225187231, true},
		{"\x80\x7f\xff\xff\xff\xff\xff\xff\xff", math.MaxInt64, true},
		{"\x80\x80\x00\x00\x00\x00\x00\x00\x00", 0, false},
		{"\xff\x80\x00\x00\x00\x00\x00\x00\x00", math.MinInt64, true},
		{"\xff\x7f\xff\xff\xff\xff\xff\xff\xff", 0, false},
		{"\xf5\xec\xd1\xc7\x7e\x5f\x26\x48\x81\x9f\x8f\x9b", 0, false},

		// Test base-8 (octal) encoded values.
		{"0000000\x00", 0, true},
		{" \x0000000\x00", 0, true},
		{" \x0000003\x00", 3, true},
		{"00000000227\x00", 0227, true},
		{"032033\x00 ", 032033, true},
		{"320330\x00 ", 0320330, true},
		{"0000660\x00 ", 0660, true},
		{"\x00 0000660\x00 ", 0660, true},
		{"0123456789abcdef", 0, false},
		{"0123456789\x00abcdef", 0, false},
		{"01234567\x0089abcdef", 342391, true},
		{"0123\x7e\x5f\x264123", 0, false},
	}

	for _, v := range vectors {
		var p parser
		got := p.parseNumeric([]byte(v.in))
		ok := (p.err == nil)
		if ok != v.ok {
			if v.ok {
				t.Errorf("parseNumeric(%q): got parsing failure, want success", v.in)
			} else {
				t.Errorf("parseNumeric(%q): got parsing success, want failure", v.in)
			}
		}
		if ok && got != v.want {
			t.Errorf("parseNumeric(%q): got %d, want %d", v.in, got, v.want)
		}
	}
}

func TestFormatNumeric(t *testing.T) {
	vectors := []struct {
		in   int64
		want string
		ok   bool
	}{
		// Test base-8 (octal) encoded values.
		{0, "0\x00", true},
		{7, "7\x00", true},
		{8, "\x80\x08", true},
		{077, "77\x00", true},
		{0100, "\x80\x00\x40", true},
		{0, "0000000\x00", true},
		{0123, "0000123\x00", true},
		{07654321, "7654321\x00", true},
		{07777777, "7777777\x00", true},
		{010000000, "\x80\x00\x00\x00\x00\x20\x00\x00", true},
		{0, "00000000000\x00", true},
		{000001234567, "00001234567\x00", true},
		{076543210321, "76543210321\x00", true},
		{012345670123, "12345670123\x00", true},
		{077777777777, "77777777777\x00", true},
		{0100000000000, "\x80\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00", true},
		{math.MaxInt64, "777777777777777777777\x00", true},

		// Test base-256 (binary) encoded values.
		{-1, "\xff", true},
		{-1, "\xff\xff", true},
		{-1, "\xff\xff\xff", true},
		{(1 << 0), "0", false},
		{(1 << 8) - 1, "\x80\xff", true},
		{(1 << 8), "0\x00", false},
		{(1 << 16) - 1, "\x80\xff\xff", true},
		{(1 << 16), "00\x00", false},
		{-1 * (1 << 0), "\xff", true},
		{-1*(1<<0) - 1, "0", false},
		{-1 * (1 << 8), "\xff\x00", true},
		{-1*(1<<8) - 1, "0\x00", false},
		{-1 * (1 << 16), "\xff\x00\x00", true},
		{-1*(1<<16) - 1, "00\x00", false},
		{537795476381659745, "0000000\x00", false},
		{537795476381659745, "\x80\x00\x00\x00\x07\x76\xa2\x22\xeb\x8a\x72\x61", true},
		{-615126028225187231, "0000000\x00", false},
		{-615126028225187231, "\xff\xff\xff\xff\xf7\x76\xa2\x22\xeb\x8a\x72\x61", true},
		{math.MaxInt64, "0000000\x00", false},
		{math.MaxInt64, "\x80\x00\x00\x00\x7f\xff\xff\xff\xff\xff\xff\xff", true},
		{math.MinInt64, "0000000\x00", false},
		{math.MinInt64, "\xff\xff\xff\xff\x80\x00\x00\x00\x00\x00\x00\x00", true},
		{math.MaxInt64, "\x80\x7f\xff\xff\xff\xff\xff\xff\xff", true},
		{math.MinInt64, "\xff\x80\x00\x00\x00\x00\x00\x00\x00", true},
	}

	for _, v := range vectors {
		var f formatter
		got := make([]byte, len(v.want))
		f.formatNumeric(got, v.in)
		ok := (f.err == nil)
		if ok != v.ok {
			if v.ok {
				t.Errorf("formatNumeric(%d): got formatting failure, want success", v.in)
			} else {
				t.Errorf("formatNumeric(%d): got formatting success, want failure", v.in)
			}
		}
		if string(got) != v.want {
			t.Errorf("formatNumeric(%d): got %q, want %q", v.in, got, v.want)
		}
	}
}

func TestFitsInOctal(t *testing.T) {
	vectors := []struct {
		input int64
		width int
		ok    bool
	}{
		{-1, 1, false},
		{-1, 2, false},
		{-1, 3, false},
		{0, 1, true},
		{0 + 1, 1, false},
		{0, 2, true},
		{07, 2, true},
		{07 + 1, 2, false},
		{0, 4, true},
		{0777, 4, true},
		{0777 + 1, 4, false},
		{0, 8, true},
		{07777777, 8, true},
		{07777777 + 1, 8, false},
		{0, 12, true},
		{077777777777, 12, true},
		{077777777777 + 1, 12, false},
		{math.MaxInt64, 22, true},
		{012345670123, 12, true},
		{01564164, 12, true},
		{-012345670123, 12, false},
		{-01564164, 12, false},
		{-1564164, 30, false},
	}

	for _, v := range vectors {
		ok := fitsInOctal(v.width, v.input)
		if ok != v.ok {
			t.Errorf("checkOctal(%d, %d): got %v, want %v", v.input, v.width, ok, v.ok)
		}
	}
}

func TestParsePAXTime(t *testing.T) {
	vectors := []struct {
		in   string
		want time.Time
		ok   bool
	}{
		{"1350244992.023960108", time.Unix(1350244992, 23960108), true},
		{"1350244992.02396010", time.Unix(1350244992, 23960100), true},
		{"1350244992.0239601089", time.Unix(1350244992, 23960108), true},
		{"1350244992.3", time.Unix(1350244992, 300000000), true},
		{"1350244992", time.Unix(1350244992, 0), true},
		{"-1.000000001", time.Unix(-1, -1e0+0e0), true},
		{"-1.000001", time.Unix(-1, -1e3+0e0), true},
		{"-1.001000", time.Unix(-1, -1e6+0e0), true},
		{"-1", time.Unix(-1, -0e0+0e0), true},
		{"-1.999000", time.Unix(-1, -1e9+1e6), true},
		{"-1.999999", time.Unix(-1, -1e9+1e3), true},
		{"-1.999999999", time.Unix(-1, -1e9+1e0), true},
		{"0.000000001", time.Unix(0, 1e0+0e0), true},
		{"0.000001", time.Unix(0, 1e3+0e0), true},
		{"0.001000", time.Unix(0, 1e6+0e0), true},
		{"0", time.Unix(0, 0e0), true},
		{"0.999000", time.Unix(0, 1e9-1e6), true},
		{"0.999999", time.Unix(0, 1e9-1e3), true},
		{"0.999999999", time.Unix(0, 1e9-1e0), true},
		{"1.000000001", time.Unix(+1, +1e0-0e0), true},
		{"1.000001", time.Unix(+1, +1e3-0e0), true},
		{"1.001000", time.Unix(+1, +1e6-0e0), true},
		{"1", time.Unix(+1, +0e0-0e0), true},
		{"1.999000", time.Unix(+1, +1e9-1e6), true},
		{"1.999999", time.Unix(+1, +1e9-1e3), true},
		{"1.999999999", time.Unix(+1, +1e9-1e0), true},
		{"-1350244992.023960108", time.Unix(-1350244992, -23960108), true},
		{"-1350244992.02396010", time.Unix(-1350244992, -23960100), true},
		{"-1350244992.0239601089", time.Unix(-1350244992, -23960108), true},
		{"-1350244992.3", time.Unix(-1350244992, -300000000), true},
		{"-1350244992", time.Unix(-1350244992, 0), true},
		{"", time.Time{}, false},
		{"0", time.Unix(0, 0), true},
		{"1.", time.Unix(1, 0), true},
		{"0.0", time.Unix(0, 0), true},
		{".5", time.Time{}, false},
		{"-1.3", time.Unix(-1, -3e8), true},
		{"-1.0", time.Unix(-1, -0e0), true},
		{"-0.0", time.Unix(-0, -0e0), true},
		{"-0.1", time.Unix(-0, -1e8), true},
		{"-0.01", time.Unix(-0, -1e7), true},
		{"-0.99", time.Unix(-0, -99e7), true},
		{"-0.98", time.Unix(-0, -98e7), true},
		{"-1.1", time.Unix(-1, -1e8), true},
		{"-1.01", time.Unix(-1, -1e7), true},
		{"-2.99", time.Unix(-2, -99e7), true},
		{"-5.98", time.Unix(-5, -98e7), true},
		{"-", time.Time{}, false},
		{"+", time.Time{}, false},
		{"-1.-1", time.Time{}, false},
		{"99999999999999999999999999999999999999999999999", time.Time{}, false},
		{"0.123456789abcdef", time.Time{}, false},
		{"foo", time.Time{}, false},
		{"\x00", time.Time{}, false},
		{"𝟵𝟴𝟳𝟲𝟱.𝟰𝟯𝟮𝟭𝟬", time.Time{}, false}, // Unicode numbers (U+1D7EC to U+1D7F5)
		{"98765﹒43210", time.Time{}, false}, // Unicode period (U+FE52)
	}

	for _, v := range vectors {
		ts, err := parsePAXTime(v.in)
		ok := (err == nil)
		if v.ok != ok {
			if v.ok {
				t.Errorf("parsePAXTime(%q): got parsing failure, want success", v.in)
			} else {
				t.Errorf("parsePAXTime(%q): got parsing success, want failure", v.in)
			}
		}
		if ok && !ts.Equal(v.want) {
			t.Errorf("parsePAXTime(%q): got (%ds %dns), want (%ds %dns)",
				v.in, ts.Unix(), ts.Nanosecond(), v.want.Unix(), v.want.Nanosecond())
		}
	}
}

func TestFormatPAXTime(t *testing.T) {
	vectors := []struct {
		sec, nsec int64
		want      string
	}{
		{1350244992, 0, "1350244992"},
		{1350244992, 300000000, "1350244992.3"},
		{1350244992, 23960100, "1350244992.0239601"},
		{1350244992, 23960108, "1350244992.023960108"},
		{+1, +1e9 - 1e0, "1.999999999"},
		{+1, +1e9 - 1e3, "1.999999"},
		{+1, +1e9 - 1e6, "1.999"},
		{+1, +0e0 - 0e0, "1"},
		{+1, +1e6 - 0e0, "1.001"},
		{+1, +1e3 - 0e0, "1.000001"},
		{+1, +1e0 - 0e0, "1.000000001"},
		{0, 1e9 - 1e0, "0.999999999"},
		{0, 1e9 - 1e3, "0.999999"},
		{0, 1e9 - 1e6, "0.999"},
		{0, 0e0, "0"},
		{0, 1e6 + 0e0, "0.001"},
		{0, 1e3 + 0e0, "0.000001"},
		{0, 1e0 + 0e0, "0.000000001"},
		{-1, -1e9 + 1e0, "-1.999999999"},
		{-1, -1e9 + 1e3, "-1.999999"},
		{-1, -1e9 + 1e6, "-1.999"},
		{-1, -0e0 + 0e0, "-1"},
		{-1, -1e6 + 0e0, "-1.001"},
		{-1, -1e3 + 0e0, "-1.000001"},
		{-1, -1e0 + 0e0, "-1.000000001"},
		{-1350244992, 0, "-1350244992"},
		{-1350244992, -300000000, "-1350244992.3"},
		{-1350244992, -23960100, "-1350244992.0239601"},
		{-1350244992, -23960108, "-1350244992.023960108"},
	}

	for _, v := range vectors {
		got := formatPAXTime(time.Unix(v.sec, v.nsec))
		if got != v.want {
			t.Errorf("formatPAXTime(%ds, %dns): got %q, want %q",
				v.sec, v.nsec, got, v.want)
		}
	}
}

func TestParsePAXRecord(t *testing.T) {
	medName := strings.Repeat("CD", 50)
	longName := strings.Repeat("AB", 100)

	vectors := []struct {
		in      string
		wantRes string
		wantKey string
		wantVal string
		ok      bool
	}{
		{"6 k=v\n\n", "\n", "k", "v", true},
		{"19 path=/etc/hosts\n", "", "path", "/etc/hosts", true},
		{"210 path=" + longName + "\nabc", "abc", "path", longName, true},
		{"110 path=" + medName + "\n", "", "path", medName, true},
		{"9 foo=ba\n", "", "foo", "ba", true},
		{"11 foo=bar\n\x00", "\x00", "foo", "bar", true},
		{"18 foo=b=\nar=\n==\x00\n", "", "foo", "b=\nar=\n==\x00", true},
		{"27 foo=hello9 foo=ba\nworld\n", "", "foo", "hello9 foo=ba\nworld", true},
		{"27 ☺☻☹=日a本b語ç\nmeow mix", "meow mix", "☺☻☹", "日a本b語ç", true},
		{"17 \x00hello=\x00world\n", "17 \x00hello=\x00world\n", "", "", false},
		{"1 k=1\n", "1 k=1\n", "", "", false},
		{"6 k~1\n", "6 k~1\n", "", "", false},
		{"6_k=1\n", "6_k=1\n", "", "", false},
		{"6 k=1 ", "6 k=1 ", "", "", false},
		{"632 k=1\n", "632 k=1\n", "", "", false},
		{"16 longkeyname=hahaha\n", "16 longkeyname=hahaha\n", "", "", false},
		{"3 somelongkey=\n", "3 somelongkey=\n", "", "", false},
		{"50 tooshort=\n", "50 tooshort=\n", "", "", false},
		{"0000000000000000000000000000000030 mtime=1432668921.098285006\n30 ctime=2147483649.15163319", "0000000000000000000000000000000030 mtime=1432668921.098285006\n30 ctime=2147483649.15163319", "mtime", "1432668921.098285006", false},
		{"06 k=v\n", "06 k=v\n", "", "", false},
		{"00006 k=v\n", "00006 k=v\n", "", "", false},
		{"000006 k=v\n", "000006 k=v\n", "", "", false},
		{"000000 k=v\n", "000000 k=v\n", "", "", false},
		{"0 k=v\n", "0 k=v\n", "", "", false},
		{"+0000005 x=\n", "+0000005 x=\n", "", "", false},
	}

	for _, v := range vectors {
		key, val, res, err := parsePAXRecord(v.in)
		ok := (err == nil)
		if ok != v.ok {
			if v.ok {
				t.Errorf("parsePAXRecord(%q): got parsing failure, want success", v.in)
			} else {
				t.Errorf("parsePAXRecord(%q): got parsing success, want failure", v.in)
			}
		}
		if v.ok && (key != v.wantKey || val != v.wantVal) {
			t.Errorf("parsePAXRecord(%q): got (%q: %q), want (%q: %q)",
				v.in, key, val, v.wantKey, v.wantVal)
		}
		if res != v.wantRes {
			t.Errorf("parsePAXRecord(%q): got residual %q, want residual %q",
				v.in, res, v.wantRes)
		}
	}
}

func TestFormatPAXRecord(t *testing.T) {
	medName := strings.Repeat("CD", 50)
	longName := strings.Repeat("AB", 100)

	vectors := []struct {
		inKey string
		inVal string
		want  string
		ok    bool
	}{
		{"k", "v", "6 k=v\n", true},
		{"path", "/etc/hosts", "19 path=/etc/hosts\n", true},
		{"path", longName, "210 path=" + longName + "\n", true},
		{"path", medName, "110 path=" + medName + "\n", true},
		{"foo", "ba", "9 foo=ba\n", true},
		{"foo", "bar", "11 foo=bar\n", true},
		{"foo", "b=\nar=\n==\x00", "18 foo=b=\nar=\n==\x00\n", true},
		{"foo", "hello9 foo=ba\nworld", "27 foo=hello9 foo=ba\nworld\n", true},
		{"☺☻☹", "日a本b語ç", "27 ☺☻☹=日a本b語ç\n", true},
		{"xhello", "\x00world", "17 xhello=\x00world\n", true},
		{"path", "null\x00", "", false},
		{"null\x00", "value", "", false},
		{paxSchilyXattr + "key", "null\x00", "26 SCHILY.xattr.key=null\x00\n", true},
	}

	for _, v := range vectors {
		got, err := formatPAXRecord(v.inKey, v.inVal)
		ok := (err == nil)
		if ok != v.ok {
			if v.ok {
				t.Errorf("formatPAXRecord(%q, %q): got format failure, want success", v.inKey, v.inVal)
			} else {
				t.Errorf("formatPAXRecord(%q, %q): got format success, want failure", v.inKey, v.inVal)
			}
		}
		if got != v.want {
			t.Errorf("formatPAXRecord(%q, %q): got %q, want %q",
				v.inKey, v.inVal, got, v.want)
		}
	}
}
```