Response:
Let's break down the thought process for analyzing the given Go code snippet.

**1. Initial Understanding: What is the File About?**

The file path `go/src/encoding/csv/reader_test.go` immediately tells us this is a test file for the `csv` package's reader functionality. The `_test.go` suffix is a standard Go convention. The `encoding/csv` part indicates it's part of the Go standard library for handling CSV (Comma Separated Values) files.

**2. Identifying the Core Purpose: Testing the CSV Reader**

The presence of a `TestRead` function, a `readTest` struct, and a `readTests` slice strongly suggest that this file is dedicated to unit testing the `csv.Reader`.

**3. Deconstructing the `readTest` Struct:**

The `readTest` struct is the key to understanding the test cases. Each field in this struct represents a different aspect of a CSV reading scenario:

*   `Name`:  A descriptive name for the test case.
*   `Input`: The raw CSV data to be processed. The special characters (§, ¶, ∑) are notable and hint at internal processing for position tracking.
*   `Output`: The expected parsed output of the CSV data. It's a `[][]string`, representing a slice of records (rows), where each record is a slice of fields (strings).
*   `Positions`:  This is likely related to error reporting and field position tracking. The `[][][2]int` structure suggests a three-level hierarchy: test case -> record -> field -> [line, column].
*   `Errors`: A slice of expected errors during parsing.
*   `Comma`: The delimiter used to separate fields (defaults to comma).
*   `Comment`: The character that marks the beginning of a comment line.
*   `UseFieldsPerRecord`:  A flag to indicate if the `FieldsPerRecord` setting is being tested.
*   `FieldsPerRecord`: The expected number of fields per record. This is important for handling inconsistent row lengths.
*   `LazyQuotes`:  A flag for handling quotes in a more lenient way.
*   `TrimLeadingSpace`:  A flag to indicate if leading spaces in fields should be trimmed.
*   `ReuseRecord`: A flag to test if the reader reuses the underlying slice for each record.

**4. Analyzing the `readTests` Slice:**

Scanning through the `readTests` slice gives concrete examples of different CSV scenarios being tested:

*   Simple cases with standard delimiters.
*   Different line endings (CRLF, bare CR).
*   Quoted fields (with and without escapes).
*   Comments.
*   Custom delimiters.
*   Error handling (malformed quotes, incorrect field counts).
*   Edge cases (trailing commas, empty lines).
*   Large input and performance considerations.

**5. Examining the `TestRead` Function:**

This function iterates through the `readTests` and performs the actual testing:

*   It uses a helper function `newReader` to create a `csv.Reader` instance configured according to the test case.
*   It calls `r.ReadAll()` to read the entire CSV input and compares the output and errors with the expected values.
*   It also calls `r.Read()` in a loop to test the record-by-record reading functionality and verifies field positions using `r.FieldPos()`.

**6. Deciphering the Special Characters (§, ¶, ∑):**

These characters are not standard CSV. Their usage within the `Input` field of `readTest` strongly suggests they are *markers* used internally by the test code to track field starts, record boundaries, and error locations. The `makePositions` function confirms this by parsing the input string and extracting position information based on these markers.

**7. Identifying Key Functionality Being Tested:**

Based on the structure and content of the test cases, we can identify the core functionalities of the `csv.Reader` being tested:

*   Parsing of standard CSV formats.
*   Handling different delimiters and quote characters.
*   Support for comments.
*   Handling quoted fields, including multi-line quotes and escaped quotes.
*   Error detection and reporting (malformed CSV).
*   Optional features like trimming leading spaces, lazy quotes, and controlling the number of fields per record.
*   Performance aspects (through benchmarking).
*   Correct tracking of field positions for error reporting.
*   The `ReuseRecord` option and its implications.

**8. Constructing Go Code Examples:**

Based on the tested functionalities, we can create illustrative Go code examples demonstrating how to use the `csv.Reader` with various configurations. This involves using the `csv.NewReader`, setting options like `Comma`, `Comment`, `LazyQuotes`, etc., and then using `Read()` or `ReadAll()`.

**9. Identifying Potential User Mistakes:**

By analyzing the error test cases and the configurable options, we can identify common mistakes users might make:

*   Incorrectly specifying the delimiter or quote character.
*   Not handling potential parsing errors.
*   Misunderstanding the behavior of `LazyQuotes`.
*   Not being aware of the `FieldsPerRecord` option and its impact on error handling.

**10. Analyzing the Benchmark Tests:**

The `BenchmarkRead` functions demonstrate how to measure the performance of the `csv.Reader` under different conditions, such as with and without `FieldsPerRecord` and with the `ReuseRecord` option. This highlights the performance implications of certain configurations.

**Self-Correction/Refinement:**

Initially, I might have overlooked the special characters and their purpose. However, seeing them consistently in the `Input` fields and the existence of `makePositions` would prompt a closer look. Similarly, the `ReuseRecord` field might not be immediately obvious, but its presence in several test cases and benchmark functions highlights its significance. Paying attention to the names of the test cases ("BadFieldCount", "BadDoubleQuotes") also provides valuable clues about the tested error conditions.
这个`go/src/encoding/csv/reader_test.go` 文件是 Go 语言标准库 `encoding/csv` 包中关于 CSV 数据读取功能的测试代码。它通过定义一系列测试用例来验证 `csv.Reader` 的各种功能和边界情况。

以下是该文件主要功能的详细列表：

1. **测试基本的 CSV 读取:**  验证 `csv.Reader` 能否正确解析简单的、标准的 CSV 格式数据，例如逗号分隔的字段和换行符分隔的记录。

2. **测试不同的行尾符:** 验证 `csv.Reader` 能否处理不同的行尾符，包括 `\n` (LF), `\r\n` (CRLF), 和单独的 `\r` (CR)。

3. **测试 RFC 4180 规范:** 验证 `csv.Reader` 是否遵循 RFC 4180 规范，特别是关于带引号的字段和双引号转义的处理。

4. **测试无行尾符的情况:** 验证 `csv.Reader` 在输入数据没有明确的行尾符时是否能正确解析。

5. **测试自定义分隔符:** 验证 `csv.Reader` 是否允许用户自定义字段分隔符（默认为逗号）。

6. **测试多行字段:** 验证 `csv.Reader` 能否正确处理包含换行符的带引号的字段。

7. **测试空行:** 验证 `csv.Reader` 在遇到空行时的行为，可以选择忽略或者返回空记录。

8. **测试字段数量一致性 (FieldsPerRecord):** 验证 `csv.Reader` 可以根据 `FieldsPerRecord` 配置来检查每条记录的字段数量是否一致，并在不一致时返回错误。

9. **测试去除前导空格 (TrimLeadingSpace):** 验证 `csv.Reader` 是否能够去除字段开头的前导空格。

10. **测试注释行:** 验证 `csv.Reader` 是否支持注释行，并可以通过配置自定义注释字符。

11. **测试惰性引号 (LazyQuotes):** 验证 `csv.Reader` 的惰性引号模式，允许字段中出现未闭合的引号。

12. **测试错误的引号:** 验证 `csv.Reader` 在遇到格式错误的引号（例如未闭合的引号）时的错误处理。

13. **测试字段数量不一致的错误处理:** 验证 `csv.Reader` 在 `FieldsPerRecord` 启用时，遇到字段数量不一致的记录时是否会返回 `ErrFieldCount` 错误。

14. **测试结尾逗号:** 验证 `csv.Reader` 能否正确处理行尾的逗号。

15. **测试 `ReuseRecord` 选项:** 验证 `csv.Reader` 的 `ReuseRecord` 选项，该选项允许在多次 `Read` 调用中重用相同的底层切片来存储记录，以提高性能。

16. **测试错误的位置信息:**  通过特殊的标记符 (`§`, `¶`, `∑`)，测试代码验证 `csv.Reader` 在解析错误时能否正确报告错误的行号和列号。

17. **测试非 ASCII 字符的逗号和注释符:** 验证 `csv.Reader` 是否支持使用非 ASCII 字符作为字段分隔符和注释符。

18. **测试超大行:** 验证 `csv.Reader` 处理包含大量字符的行的能力。

19. **测试包含 `\r` 的引号字段:** 验证 `csv.Reader` 处理引号字段中包含 `\r` 字符的情况。

20. **测试双引号的处理:**  验证 `csv.Reader` 如何处理字段中的双引号，包括转义的双引号。

21. **测试无效的逗号和注释符:** 验证 `csv.Reader` 对于无效的逗号和注释符（例如 `\n`, `\r`, `"`) 是否能正确返回错误。

**该文件是 `encoding/csv` 包中 `Reader` 结构体的功能实现的测试。**  `csv.Reader` 用于从 `io.Reader` 中读取 CSV 格式的数据，并将其解析为字符串切片的切片（`[][]string`），其中每个内部切片代表一行记录，每个字符串代表一个字段。

**Go 代码示例说明 `csv.Reader` 的使用:**

假设我们有一个包含以下 CSV 数据的字符串：

```
Name,Age,City
Alice,30,New York
Bob,25,London
Charlie,35,Paris
```

我们可以使用 `csv.Reader` 来读取和解析这段数据：

```go
package main

import (
	"encoding/csv"
	"fmt"
	"strings"
)

func main() {
	csvData := `Name,Age,City
Alice,30,New York
Bob,25,London
Charlie,35,Paris
`

	reader := csv.NewReader(strings.NewReader(csvData))

	// 读取所有记录
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV:", err)
		return
	}

	// 打印读取到的记录
	for _, record := range records {
		fmt.Println(record)
	}

	fmt.Println("\n逐行读取：")

	reader = csv.NewReader(strings.NewReader(csvData)) // 重新创建 Reader

	// 逐行读取记录
	for {
		record, err := reader.Read()
		if err != nil {
			if err.Error() == "EOF" {
				break // 读取完毕
			}
			fmt.Println("Error reading record:", err)
			return
		}
		fmt.Println(record)
	}
}
```

**假设的输入与输出：**

对于上述代码示例，假设的输入是 `csvData` 字符串。输出将会是：

```
[Name Age City]
[Alice 30 New York]
[Bob 25 London]
[Charlie 35 Paris]

逐行读取：
[Name Age City]
[Alice 30 New York]
[Bob 25 London]
[Charlie 35 Paris]
```

**代码推理：**

测试代码中使用了特殊的符号 `§`, `¶`, `∑` 来辅助定位字段和错误位置。

*   `§` 标记一个字段的开始。
*   `¶` 标记一条记录的结束（换行符）。
*   `∑` 标记一个错误的发生位置。

`makePositions` 函数会解析测试输入字符串，提取出这些标记的位置信息，用于后续的错误位置验证。例如，如果一个测试用例的 `Input` 是 `"§a,§b∑,§c\n"`,  `makePositions` 会记录字段 "b" 的错误发生在第二行（假设这是第一行数据）的某个列。

**命令行参数：**

`encoding/csv` 包本身并不直接处理命令行参数。 它的作用是解析 CSV 数据。如果需要在命令行中使用 CSV 数据，你需要自己编写代码来读取文件或标准输入，然后使用 `csv.Reader` 来解析。例如：

```go
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
)

func main() {
	filePath := flag.String("file", "", "Path to the CSV file")
	flag.Parse()

	if *filePath == "" {
		fmt.Println("Please provide a CSV file path using the -file flag.")
		return
	}

	file, err := os.Open(*filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)

	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV:", err)
		return
	}

	for _, record := range records {
		fmt.Println(record)
	}
}
```

运行此代码的命令示例：

```bash
go run your_program.go -file data.csv
```

**使用者易犯错的点：**

1. **忘记处理错误:**  `csv.Reader` 的 `Read` 和 `ReadAll` 方法都会返回错误，使用者容易忘记检查和处理这些错误，尤其是在解析不规范的 CSV 数据时。

    ```go
    reader := csv.NewReader(strings.NewReader("invalid,csv"))
    records, _ := reader.ReadAll() // 忽略了错误
    fmt.Println(records) // 可能得到不完整或错误的结果
    ```

2. **错误地假设分隔符:**  CSV 并不总是以逗号分隔。使用者可能错误地假设分隔符是逗号，而实际文件使用了其他分隔符（如分号、制表符）。

    ```go
    reader := csv.NewReader(strings.NewReader("field1;field2")) // 数据用分号分隔
    records, _ := reader.ReadAll()
    fmt.Println(records) // 可能得到一个包含整个字符串的记录

    // 正确的做法是设置分隔符
    reader.Comma = ';'
    records, _ = reader.ReadAll()
    fmt.Println(records) // 正确解析
    ```

3. **不理解 `LazyQuotes` 的行为:**  `LazyQuotes` 允许字段中出现未闭合的引号。使用者如果不理解其行为，可能会在期望严格的引号处理时得到意外的结果。

    ```go
    reader := csv.NewReader(strings.NewReader(`"a,b`))
    records, _ := reader.ReadAll()
    fmt.Println(records) // 默认 LazyQuotes 为 false，会报错

    reader.LazyQuotes = true
    records, _ = reader.ReadAll()
    fmt.Println(records) // 启用 LazyQuotes 后，可以解析
    ```

4. **混淆 `FieldsPerRecord` 的作用:**  使用者可能不清楚 `FieldsPerRecord` 用于验证每条记录的字段数量一致性，或者错误地设置了这个值。

    ```go
    reader := csv.NewReader(strings.NewReader("a,b\nc,d,e"))
    reader.FieldsPerRecord = 2 // 期望每条记录有 2 个字段
    records, err := reader.ReadAll()
    fmt.Println(records, err) // 第二条记录字段数不匹配，会返回错误
    ```

理解这些测试用例有助于开发者更好地使用 `encoding/csv` 包，并避免常见的错误。

Prompt: 
```
这是路径为go/src/encoding/csv/reader_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package csv

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

type readTest struct {
	Name      string
	Input     string
	Output    [][]string
	Positions [][][2]int
	Errors    []error

	// These fields are copied into the Reader
	Comma              rune
	Comment            rune
	UseFieldsPerRecord bool // false (default) means FieldsPerRecord is -1
	FieldsPerRecord    int
	LazyQuotes         bool
	TrimLeadingSpace   bool
	ReuseRecord        bool
}

// In these tests, the §, ¶ and ∑ characters in readTest.Input are used to denote
// the start of a field, a record boundary and the position of an error respectively.
// They are removed before parsing and are used to verify the position
// information reported by FieldPos.

var readTests = []readTest{{
	Name:   "Simple",
	Input:  "§a,§b,§c\n",
	Output: [][]string{{"a", "b", "c"}},
}, {
	Name:   "CRLF",
	Input:  "§a,§b\r\n¶§c,§d\r\n",
	Output: [][]string{{"a", "b"}, {"c", "d"}},
}, {
	Name:   "BareCR",
	Input:  "§a,§b\rc,§d\r\n",
	Output: [][]string{{"a", "b\rc", "d"}},
}, {
	Name: "RFC4180test",
	Input: `§#field1,§field2,§field3
¶§"aaa",§"bb
b",§"ccc"
¶§"a,a",§"b""bb",§"ccc"
¶§zzz,§yyy,§xxx
`,
	Output: [][]string{
		{"#field1", "field2", "field3"},
		{"aaa", "bb\nb", "ccc"},
		{"a,a", `b"bb`, "ccc"},
		{"zzz", "yyy", "xxx"},
	},
	UseFieldsPerRecord: true,
	FieldsPerRecord:    0,
}, {
	Name:   "NoEOLTest",
	Input:  "§a,§b,§c",
	Output: [][]string{{"a", "b", "c"}},
}, {
	Name:   "Semicolon",
	Input:  "§a;§b;§c\n",
	Output: [][]string{{"a", "b", "c"}},
	Comma:  ';',
}, {
	Name: "MultiLine",
	Input: `§"two
line",§"one line",§"three
line
field"`,
	Output: [][]string{{"two\nline", "one line", "three\nline\nfield"}},
}, {
	Name:  "BlankLine",
	Input: "§a,§b,§c\n\n¶§d,§e,§f\n\n",
	Output: [][]string{
		{"a", "b", "c"},
		{"d", "e", "f"},
	},
}, {
	Name:  "BlankLineFieldCount",
	Input: "§a,§b,§c\n\n¶§d,§e,§f\n\n",
	Output: [][]string{
		{"a", "b", "c"},
		{"d", "e", "f"},
	},
	UseFieldsPerRecord: true,
	FieldsPerRecord:    0,
}, {
	Name:             "TrimSpace",
	Input:            " §a,  §b,   §c\n",
	Output:           [][]string{{"a", "b", "c"}},
	TrimLeadingSpace: true,
}, {
	Name:   "LeadingSpace",
	Input:  "§ a,§  b,§   c\n",
	Output: [][]string{{" a", "  b", "   c"}},
}, {
	Name:    "Comment",
	Input:   "#1,2,3\n§a,§b,§c\n#comment",
	Output:  [][]string{{"a", "b", "c"}},
	Comment: '#',
}, {
	Name:   "NoComment",
	Input:  "§#1,§2,§3\n¶§a,§b,§c",
	Output: [][]string{{"#1", "2", "3"}, {"a", "b", "c"}},
}, {
	Name:       "LazyQuotes",
	Input:      `§a "word",§"1"2",§a",§"b`,
	Output:     [][]string{{`a "word"`, `1"2`, `a"`, `b`}},
	LazyQuotes: true,
}, {
	Name:       "BareQuotes",
	Input:      `§a "word",§"1"2",§a"`,
	Output:     [][]string{{`a "word"`, `1"2`, `a"`}},
	LazyQuotes: true,
}, {
	Name:       "BareDoubleQuotes",
	Input:      `§a""b,§c`,
	Output:     [][]string{{`a""b`, `c`}},
	LazyQuotes: true,
}, {
	Name:   "BadDoubleQuotes",
	Input:  `§a∑""b,c`,
	Errors: []error{&ParseError{Err: ErrBareQuote}},
}, {
	Name:             "TrimQuote",
	Input:            ` §"a",§" b",§c`,
	Output:           [][]string{{"a", " b", "c"}},
	TrimLeadingSpace: true,
}, {
	Name:   "BadBareQuote",
	Input:  `§a ∑"word","b"`,
	Errors: []error{&ParseError{Err: ErrBareQuote}},
}, {
	Name:   "BadTrailingQuote",
	Input:  `§"a word",b∑"`,
	Errors: []error{&ParseError{Err: ErrBareQuote}},
}, {
	Name:   "ExtraneousQuote",
	Input:  `§"a ∑"word","b"`,
	Errors: []error{&ParseError{Err: ErrQuote}},
}, {
	Name:               "BadFieldCount",
	Input:              "§a,§b,§c\n¶∑§d,§e",
	Errors:             []error{nil, &ParseError{Err: ErrFieldCount}},
	Output:             [][]string{{"a", "b", "c"}, {"d", "e"}},
	UseFieldsPerRecord: true,
	FieldsPerRecord:    0,
}, {
	Name:               "BadFieldCountMultiple",
	Input:              "§a,§b,§c\n¶∑§d,§e\n¶∑§f",
	Errors:             []error{nil, &ParseError{Err: ErrFieldCount}, &ParseError{Err: ErrFieldCount}},
	Output:             [][]string{{"a", "b", "c"}, {"d", "e"}, {"f"}},
	UseFieldsPerRecord: true,
	FieldsPerRecord:    0,
}, {
	Name:               "BadFieldCount1",
	Input:              `§∑a,§b,§c`,
	Errors:             []error{&ParseError{Err: ErrFieldCount}},
	Output:             [][]string{{"a", "b", "c"}},
	UseFieldsPerRecord: true,
	FieldsPerRecord:    2,
}, {
	Name:   "FieldCount",
	Input:  "§a,§b,§c\n¶§d,§e",
	Output: [][]string{{"a", "b", "c"}, {"d", "e"}},
}, {
	Name:   "TrailingCommaEOF",
	Input:  "§a,§b,§c,§",
	Output: [][]string{{"a", "b", "c", ""}},
}, {
	Name:   "TrailingCommaEOL",
	Input:  "§a,§b,§c,§\n",
	Output: [][]string{{"a", "b", "c", ""}},
}, {
	Name:             "TrailingCommaSpaceEOF",
	Input:            "§a,§b,§c, §",
	Output:           [][]string{{"a", "b", "c", ""}},
	TrimLeadingSpace: true,
}, {
	Name:             "TrailingCommaSpaceEOL",
	Input:            "§a,§b,§c, §\n",
	Output:           [][]string{{"a", "b", "c", ""}},
	TrimLeadingSpace: true,
}, {
	Name:             "TrailingCommaLine3",
	Input:            "§a,§b,§c\n¶§d,§e,§f\n¶§g,§hi,§",
	Output:           [][]string{{"a", "b", "c"}, {"d", "e", "f"}, {"g", "hi", ""}},
	TrimLeadingSpace: true,
}, {
	Name:   "NotTrailingComma3",
	Input:  "§a,§b,§c,§ \n",
	Output: [][]string{{"a", "b", "c", " "}},
}, {
	Name: "CommaFieldTest",
	Input: `§x,§y,§z,§w
¶§x,§y,§z,§
¶§x,§y,§,§
¶§x,§,§,§
¶§,§,§,§
¶§"x",§"y",§"z",§"w"
¶§"x",§"y",§"z",§""
¶§"x",§"y",§"",§""
¶§"x",§"",§"",§""
¶§"",§"",§"",§""
`,
	Output: [][]string{
		{"x", "y", "z", "w"},
		{"x", "y", "z", ""},
		{"x", "y", "", ""},
		{"x", "", "", ""},
		{"", "", "", ""},
		{"x", "y", "z", "w"},
		{"x", "y", "z", ""},
		{"x", "y", "", ""},
		{"x", "", "", ""},
		{"", "", "", ""},
	},
}, {
	Name:  "TrailingCommaIneffective1",
	Input: "§a,§b,§\n¶§c,§d,§e",
	Output: [][]string{
		{"a", "b", ""},
		{"c", "d", "e"},
	},
	TrimLeadingSpace: true,
}, {
	Name:  "ReadAllReuseRecord",
	Input: "§a,§b\n¶§c,§d",
	Output: [][]string{
		{"a", "b"},
		{"c", "d"},
	},
	ReuseRecord: true,
}, {
	Name:   "StartLine1", // Issue 19019
	Input:  "§a,\"b\nc∑\"d,e",
	Errors: []error{&ParseError{Err: ErrQuote}},
}, {
	Name:   "StartLine2",
	Input:  "§a,§b\n¶§\"d\n\n,e∑",
	Errors: []error{nil, &ParseError{Err: ErrQuote}},
	Output: [][]string{{"a", "b"}},
}, {
	Name:  "CRLFInQuotedField", // Issue 21201
	Input: "§A,§\"Hello\r\nHi\",§B\r\n",
	Output: [][]string{
		{"A", "Hello\nHi", "B"},
	},
}, {
	Name:   "BinaryBlobField", // Issue 19410
	Input:  "§x09\x41\xb4\x1c,§aktau",
	Output: [][]string{{"x09A\xb4\x1c", "aktau"}},
}, {
	Name:   "TrailingCR",
	Input:  "§field1,§field2\r",
	Output: [][]string{{"field1", "field2"}},
}, {
	Name:   "QuotedTrailingCR",
	Input:  "§\"field\"\r",
	Output: [][]string{{"field"}},
}, {
	Name:   "QuotedTrailingCRCR",
	Input:  "§\"field∑\"\r\r",
	Errors: []error{&ParseError{Err: ErrQuote}},
}, {
	Name:   "FieldCR",
	Input:  "§field\rfield\r",
	Output: [][]string{{"field\rfield"}},
}, {
	Name:   "FieldCRCR",
	Input:  "§field\r\rfield\r\r",
	Output: [][]string{{"field\r\rfield\r"}},
}, {
	Name:   "FieldCRCRLF",
	Input:  "§field\r\r\n¶§field\r\r\n",
	Output: [][]string{{"field\r"}, {"field\r"}},
}, {
	Name:   "FieldCRCRLFCR",
	Input:  "§field\r\r\n¶§\rfield\r\r\n\r",
	Output: [][]string{{"field\r"}, {"\rfield\r"}},
}, {
	Name:   "FieldCRCRLFCRCR",
	Input:  "§field\r\r\n¶§\r\rfield\r\r\n¶§\r\r",
	Output: [][]string{{"field\r"}, {"\r\rfield\r"}, {"\r"}},
}, {
	Name:  "MultiFieldCRCRLFCRCR",
	Input: "§field1,§field2\r\r\n¶§\r\rfield1,§field2\r\r\n¶§\r\r,§",
	Output: [][]string{
		{"field1", "field2\r"},
		{"\r\rfield1", "field2\r"},
		{"\r\r", ""},
	},
}, {
	Name:             "NonASCIICommaAndComment",
	Input:            "§a£§b,c£ \t§d,e\n€ comment\n",
	Output:           [][]string{{"a", "b,c", "d,e"}},
	TrimLeadingSpace: true,
	Comma:            '£',
	Comment:          '€',
}, {
	Name:    "NonASCIICommaAndCommentWithQuotes",
	Input:   "§a€§\"  b,\"€§ c\nλ comment\n",
	Output:  [][]string{{"a", "  b,", " c"}},
	Comma:   '€',
	Comment: 'λ',
}, {
	// λ and θ start with the same byte.
	// This tests that the parser doesn't confuse such characters.
	Name:    "NonASCIICommaConfusion",
	Input:   "§\"abθcd\"λ§efθgh",
	Output:  [][]string{{"abθcd", "efθgh"}},
	Comma:   'λ',
	Comment: '€',
}, {
	Name:    "NonASCIICommentConfusion",
	Input:   "§λ\n¶§λ\nθ\n¶§λ\n",
	Output:  [][]string{{"λ"}, {"λ"}, {"λ"}},
	Comment: 'θ',
}, {
	Name:   "QuotedFieldMultipleLF",
	Input:  "§\"\n\n\n\n\"",
	Output: [][]string{{"\n\n\n\n"}},
}, {
	Name:  "MultipleCRLF",
	Input: "\r\n\r\n\r\n\r\n",
}, {
	// The implementation may read each line in several chunks if it doesn't fit entirely
	// in the read buffer, so we should test the code to handle that condition.
	Name:    "HugeLines",
	Input:   strings.Repeat("#ignore\n", 10000) + "§" + strings.Repeat("@", 5000) + ",§" + strings.Repeat("*", 5000),
	Output:  [][]string{{strings.Repeat("@", 5000), strings.Repeat("*", 5000)}},
	Comment: '#',
}, {
	Name:   "QuoteWithTrailingCRLF",
	Input:  "§\"foo∑\"bar\"\r\n",
	Errors: []error{&ParseError{Err: ErrQuote}},
}, {
	Name:       "LazyQuoteWithTrailingCRLF",
	Input:      "§\"foo\"bar\"\r\n",
	Output:     [][]string{{`foo"bar`}},
	LazyQuotes: true,
}, {
	Name:   "DoubleQuoteWithTrailingCRLF",
	Input:  "§\"foo\"\"bar\"\r\n",
	Output: [][]string{{`foo"bar`}},
}, {
	Name:   "EvenQuotes",
	Input:  `§""""""""`,
	Output: [][]string{{`"""`}},
}, {
	Name:   "OddQuotes",
	Input:  `§"""""""∑`,
	Errors: []error{&ParseError{Err: ErrQuote}},
}, {
	Name:       "LazyOddQuotes",
	Input:      `§"""""""`,
	Output:     [][]string{{`"""`}},
	LazyQuotes: true,
}, {
	Name:   "BadComma1",
	Comma:  '\n',
	Errors: []error{errInvalidDelim},
}, {
	Name:   "BadComma2",
	Comma:  '\r',
	Errors: []error{errInvalidDelim},
}, {
	Name:   "BadComma3",
	Comma:  '"',
	Errors: []error{errInvalidDelim},
}, {
	Name:   "BadComma4",
	Comma:  utf8.RuneError,
	Errors: []error{errInvalidDelim},
}, {
	Name:    "BadComment1",
	Comment: '\n',
	Errors:  []error{errInvalidDelim},
}, {
	Name:    "BadComment2",
	Comment: '\r',
	Errors:  []error{errInvalidDelim},
}, {
	Name:    "BadComment3",
	Comment: utf8.RuneError,
	Errors:  []error{errInvalidDelim},
}, {
	Name:    "BadCommaComment",
	Comma:   'X',
	Comment: 'X',
	Errors:  []error{errInvalidDelim},
}}

func TestRead(t *testing.T) {
	newReader := func(tt readTest) (*Reader, [][][2]int, map[int][2]int, string) {
		positions, errPositions, input := makePositions(tt.Input)
		r := NewReader(strings.NewReader(input))

		if tt.Comma != 0 {
			r.Comma = tt.Comma
		}
		r.Comment = tt.Comment
		if tt.UseFieldsPerRecord {
			r.FieldsPerRecord = tt.FieldsPerRecord
		} else {
			r.FieldsPerRecord = -1
		}
		r.LazyQuotes = tt.LazyQuotes
		r.TrimLeadingSpace = tt.TrimLeadingSpace
		r.ReuseRecord = tt.ReuseRecord
		return r, positions, errPositions, input
	}

	for _, tt := range readTests {
		t.Run(tt.Name, func(t *testing.T) {
			r, positions, errPositions, input := newReader(tt)
			out, err := r.ReadAll()
			if wantErr := firstError(tt.Errors, positions, errPositions); wantErr != nil {
				if !reflect.DeepEqual(err, wantErr) {
					t.Fatalf("ReadAll() error mismatch:\ngot  %v (%#v)\nwant %v (%#v)", err, err, wantErr, wantErr)
				}
				if out != nil {
					t.Fatalf("ReadAll() output:\ngot  %q\nwant nil", out)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected Readall() error: %v", err)
				}
				if !reflect.DeepEqual(out, tt.Output) {
					t.Fatalf("ReadAll() output:\ngot  %q\nwant %q", out, tt.Output)
				}
			}

			// Check input offset after call ReadAll()
			inputByteSize := len(input)
			inputOffset := r.InputOffset()
			if err == nil && int64(inputByteSize) != inputOffset {
				t.Errorf("wrong input offset after call ReadAll():\ngot:  %d\nwant: %d\ninput: %s", inputOffset, inputByteSize, input)
			}

			// Check field and error positions.
			r, _, _, _ = newReader(tt)
			for recNum := 0; ; recNum++ {
				rec, err := r.Read()
				var wantErr error
				if recNum < len(tt.Errors) && tt.Errors[recNum] != nil {
					wantErr = errorWithPosition(tt.Errors[recNum], recNum, positions, errPositions)
				} else if recNum >= len(tt.Output) {
					wantErr = io.EOF
				}
				if !reflect.DeepEqual(err, wantErr) {
					t.Fatalf("Read() error at record %d:\ngot %v (%#v)\nwant %v (%#v)", recNum, err, err, wantErr, wantErr)
				}
				// ErrFieldCount is explicitly non-fatal.
				if err != nil && !errors.Is(err, ErrFieldCount) {
					if recNum < len(tt.Output) {
						t.Fatalf("need more records; got %d want %d", recNum, len(tt.Output))
					}
					break
				}
				if got, want := rec, tt.Output[recNum]; !slices.Equal(got, want) {
					t.Errorf("Read vs ReadAll mismatch;\ngot %q\nwant %q", got, want)
				}
				pos := positions[recNum]
				if len(pos) != len(rec) {
					t.Fatalf("mismatched position length at record %d", recNum)
				}
				for i := range rec {
					line, col := r.FieldPos(i)
					if got, want := [2]int{line, col}, pos[i]; got != want {
						t.Errorf("position mismatch at record %d, field %d;\ngot %v\nwant %v", recNum, i, got, want)
					}
				}
			}
		})
	}
}

// firstError returns the first non-nil error in errs,
// with the position adjusted according to the error's
// index inside positions.
func firstError(errs []error, positions [][][2]int, errPositions map[int][2]int) error {
	for i, err := range errs {
		if err != nil {
			return errorWithPosition(err, i, positions, errPositions)
		}
	}
	return nil
}

func errorWithPosition(err error, recNum int, positions [][][2]int, errPositions map[int][2]int) error {
	parseErr, ok := err.(*ParseError)
	if !ok {
		return err
	}
	if recNum >= len(positions) {
		panic(fmt.Errorf("no positions found for error at record %d", recNum))
	}
	errPos, ok := errPositions[recNum]
	if !ok {
		panic(fmt.Errorf("no error position found for error at record %d", recNum))
	}
	parseErr1 := *parseErr
	parseErr1.StartLine = positions[recNum][0][0]
	parseErr1.Line = errPos[0]
	parseErr1.Column = errPos[1]
	return &parseErr1
}

// makePositions returns the expected field positions of all
// the fields in text, the positions of any errors, and the text with the position markers
// removed.
//
// The start of each field is marked with a § symbol;
// CSV lines are separated by ¶ symbols;
// Error positions are marked with ∑ symbols.
func makePositions(text string) ([][][2]int, map[int][2]int, string) {
	buf := make([]byte, 0, len(text))
	var positions [][][2]int
	errPositions := make(map[int][2]int)
	line, col := 1, 1
	recNum := 0

	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		switch r {
		case '\n':
			line++
			col = 1
			buf = append(buf, '\n')
		case '§':
			if len(positions) == 0 {
				positions = append(positions, [][2]int{})
			}
			positions[len(positions)-1] = append(positions[len(positions)-1], [2]int{line, col})
		case '¶':
			positions = append(positions, [][2]int{})
			recNum++
		case '∑':
			errPositions[recNum] = [2]int{line, col}
		default:
			buf = append(buf, text[:size]...)
			col += size
		}
		text = text[size:]
	}
	return positions, errPositions, string(buf)
}

// nTimes is an io.Reader which yields the string s n times.
type nTimes struct {
	s   string
	n   int
	off int
}

func (r *nTimes) Read(p []byte) (n int, err error) {
	for {
		if r.n <= 0 || r.s == "" {
			return n, io.EOF
		}
		n0 := copy(p, r.s[r.off:])
		p = p[n0:]
		n += n0
		r.off += n0
		if r.off == len(r.s) {
			r.off = 0
			r.n--
		}
		if len(p) == 0 {
			return
		}
	}
}

// benchmarkRead measures reading the provided CSV rows data.
// initReader, if non-nil, modifies the Reader before it's used.
func benchmarkRead(b *testing.B, initReader func(*Reader), rows string) {
	b.ReportAllocs()
	r := NewReader(&nTimes{s: rows, n: b.N})
	if initReader != nil {
		initReader(r)
	}
	for {
		_, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			b.Fatal(err)
		}
	}
}

const benchmarkCSVData = `x,y,z,w
x,y,z,
x,y,,
x,,,
,,,
"x","y","z","w"
"x","y","z",""
"x","y","",""
"x","","",""
"","","",""
`

func BenchmarkRead(b *testing.B) {
	benchmarkRead(b, nil, benchmarkCSVData)
}

func BenchmarkReadWithFieldsPerRecord(b *testing.B) {
	benchmarkRead(b, func(r *Reader) { r.FieldsPerRecord = 4 }, benchmarkCSVData)
}

func BenchmarkReadWithoutFieldsPerRecord(b *testing.B) {
	benchmarkRead(b, func(r *Reader) { r.FieldsPerRecord = -1 }, benchmarkCSVData)
}

func BenchmarkReadLargeFields(b *testing.B) {
	benchmarkRead(b, nil, strings.Repeat(`xxxxxxxxxxxxxxxx,yyyyyyyyyyyyyyyy,zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww,vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
xxxxxxxxxxxxxxxxxxxxxxxx,yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy,zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww,vvvv
,,zzzz,wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww,vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy,zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww,vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
`, 3))
}

func BenchmarkReadReuseRecord(b *testing.B) {
	benchmarkRead(b, func(r *Reader) { r.ReuseRecord = true }, benchmarkCSVData)
}

func BenchmarkReadReuseRecordWithFieldsPerRecord(b *testing.B) {
	benchmarkRead(b, func(r *Reader) { r.ReuseRecord = true; r.FieldsPerRecord = 4 }, benchmarkCSVData)
}

func BenchmarkReadReuseRecordWithoutFieldsPerRecord(b *testing.B) {
	benchmarkRead(b, func(r *Reader) { r.ReuseRecord = true; r.FieldsPerRecord = -1 }, benchmarkCSVData)
}

func BenchmarkReadReuseRecordLargeFields(b *testing.B) {
	benchmarkRead(b, func(r *Reader) { r.ReuseRecord = true }, strings.Repeat(`xxxxxxxxxxxxxxxx,yyyyyyyyyyyyyyyy,zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww,vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
xxxxxxxxxxxxxxxxxxxxxxxx,yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy,zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww,vvvv
,,zzzz,wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww,vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy,zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww,vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
`, 3))
}

"""



```