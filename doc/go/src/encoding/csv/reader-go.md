Response:
The user wants to understand the functionality of the provided Go code snippet, which is a part of the `encoding/csv` package's `reader.go` file. I need to:

1. **List the functionalities:**  Identify the key operations the code performs, like reading CSV records, handling different quoting rules, dealing with errors, etc.
2. **Infer the Go language feature implemented:** Determine what higher-level CSV reading functionality this code provides within the Go standard library.
3. **Provide a Go code example:**  Demonstrate how to use the inferred Go feature, including setup, reading data, and handling potential errors. This example should include sample input and the expected output.
4. **Explain any command-line parameter handling:**  Although the code doesn't directly handle command-line arguments, the `csv` package might be used in programs that do. I need to consider if there's an indirect relationship. Looking at the code, there are no command-line parameters being directly processed.
5. **Point out common mistakes:** Identify potential pitfalls users might encounter when using this functionality, backed by examples if possible.

**Functionalities:**

* Reading CSV data from an `io.Reader`.
* Handling different field delimiters (defaulting to a comma).
* Supporting comment lines.
* Enforcing a fixed number of fields per record (optional).
* Handling quoted fields, including escaped quotes.
* Providing options for lazy quoting and trimming leading spaces.
* Reporting parsing errors with line and column numbers.
* Option to reuse the underlying slice for performance.

**Inferred Go language feature:**  This code snippet is the implementation of the `csv.Reader` type, which is used to read CSV data.

**Go code example:**  I'll create a simple example that reads CSV data from a string.

**Command-line parameters:** The `encoding/csv` package doesn't directly handle command-line arguments. Users would typically read CSV files specified as command-line arguments using other parts of the Go standard library, like `os.Open` and then pass the resulting `io.Reader` to `csv.NewReader`.

**Common mistakes:** I need to think about common errors like incorrect delimiters, improper quoting, and assumptions about the number of fields.
这段代码是 Go 语言 `encoding/csv` 包中 `reader.go` 文件的一部分，它实现了 **读取 CSV (逗号分隔值) 文件的功能**。更具体地说，它定义了 `Reader` 类型以及与读取 CSV 数据相关的方法。

**主要功能列举如下：**

1. **从 `io.Reader` 读取数据:**  `Reader` 结构体接收一个 `io.Reader` 接口作为输入，可以从文件、网络连接或其他数据源读取 CSV 数据。
2. **定义字段分隔符:**  可以通过 `Comma` 字段设置字段之间的分隔符，默认为逗号 `,`。
3. **定义注释字符:**  可以通过 `Comment` 字段设置注释字符，以该字符开头的行将被忽略。
4. **控制每条记录的字段数量:**  `FieldsPerRecord` 字段可以设置期望的每条记录的字段数量。
    * 如果为正数，`Read` 方法会检查每条记录的字段数是否与该值相等，不相等则返回 `ErrFieldCount` 错误。
    * 如果为 0，`Read` 方法会将第一条记录的字段数作为后续记录的标准。
    * 如果为负数，则不对字段数进行检查，允许记录具有可变的字段数。
5. **处理带引号的字段:**  能够正确解析用双引号 `"` 包围的字段。
6. **处理引号内的转义:**  在带引号的字段中，两个连续的双引号 `""` 被解释为一个双引号 `"`。
7. **处理带引号字段中的换行符和分隔符:**  允许带引号的字段中包含换行符和定义的分隔符。
8. **支持宽松引号 (Lazy Quotes):**  如果 `LazyQuotes` 为 `true`，则允许未被引号包围的字段中出现引号，以及带引号的字段中出现未成对的引号。
9. **去除字段前导空格:**  如果 `TrimLeadingSpace` 为 `true`，则会忽略字段开头的空格。
10. **重用记录切片 (可选):**  如果 `ReuseRecord` 为 `true`，则 `Read` 方法可能会返回与上次调用共享底层数组的切片，以提高性能。
11. **报告解析错误:**  如果 CSV 数据格式不正确，会返回 `ParseError` 类型的错误，其中包含错误发生的行号和列号等信息。
12. **提供 `ReadAll` 方法:**  一次性读取所有剩余的记录。
13. **提供 `FieldPos` 方法:**  返回最近一次 `Read` 方法返回的记录中指定字段的起始行号和列号。
14. **提供 `InputOffset` 方法:** 返回当前读取位置在输入流中的字节偏移量。
15. **规范化换行符:**  将输入中的 `\r\n` 序列转换为 `\n`。
16. **忽略空行:**  空白行会被忽略。
17. **移除行尾的回车符:**  行尾换行符前的回车符会被静默移除。

**这是一个 Go 语言标准库中用于处理 CSV 文件的功能实现。**

**Go 代码示例：**

假设我们有以下 CSV 格式的字符串数据：

```
name,age,city
"Alice, Smith",30,New York
Bob,25,"Los Angeles"
```

我们可以使用 `csv.Reader` 来读取这些数据：

```go
package main

import (
	"encoding/csv"
	"fmt"
	"strings"
)

func main() {
	csvData := `name,age,city
"Alice, Smith",30,New York
Bob,25,"Los Angeles"`

	r := csv.NewReader(strings.NewReader(csvData))

	// 设置字段分隔符 (默认为逗号，这里可以省略)
	// r.Comma = ','

	// 读取标题行
	header, err := r.Read()
	if err != nil {
		fmt.Println("Error reading header:", err)
		return
	}
	fmt.Println("Header:", header)

	// 循环读取每一行数据
	for {
		record, err := r.Read()
		if err != nil {
			if err.Error() == "EOF" { // io.EOF 的错误信息是 "EOF"
				break // 读取完毕
			}
			fmt.Println("Error reading record:", err)
			continue
		}
		fmt.Println("Record:", record)
	}
}
```

**假设输入：** 上述 `csvData` 字符串。

**预期输出：**

```
Header: [name age city]
Record: [Alice, Smith 30 New York]
Record: [Bob 25 Los Angeles]
```

**代码推理：**

1. `strings.NewReader(csvData)` 创建了一个可以从字符串读取数据的 `io.Reader`。
2. `csv.NewReader()` 创建了一个新的 `csv.Reader` 实例，并将字符串读取器作为输入。
3. 第一次调用 `r.Read()` 读取了 CSV 的第一行，即标题行 `name,age,city`。
4. 接下来的 `for` 循环不断调用 `r.Read()` 来读取后续的每一条记录。
5. 当 `r.Read()` 返回 `io.EOF` 错误时，表示已经读取到文件末尾，循环结束。
6. 注意，带引号的字段 `"Alice, Smith"` 中的逗号被视为字段内容的一部分。

**命令行参数处理：**

这段代码本身并没有直接处理命令行参数。`encoding/csv` 包专注于 CSV 数据的读取和写入。如果要从命令行指定 CSV 文件路径，你需要使用 `os` 包来打开文件，并将返回的 `os.File` 类型作为 `csv.NewReader` 的输入。

例如：

```go
package main

import (
	"encoding/csv"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <csv_file_path>")
		return
	}

	filePath := os.Args[1]

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	r := csv.NewReader(file)

	// ... (读取 CSV 数据的代码与上面的例子类似) ...
}
```

在这个例子中，命令行参数 `<csv_file_path>` 通过 `os.Args[1]` 获取，然后 `os.Open()` 函数打开指定的文件，返回的 `file` 被传递给 `csv.NewReader()`。

**使用者易犯错的点：**

1. **错误的字段分隔符：** 如果 CSV 文件使用的分隔符不是逗号，而使用者没有正确设置 `r.Comma`，会导致数据解析错误。

   **例如：** 如果 CSV 文件使用分号 `;` 作为分隔符，但代码中仍然使用默认的逗号，那么一行数据会被错误地解析为一个包含多个逗号的字段。

   ```go
   // 假设 CSV 数据为 "name;age;city\nAlice;30;New York"
   csvData := "name;age;city\nAlice;30;New York"
   r := csv.NewReader(strings.NewReader(csvData))
   record, _ := r.Read()
   fmt.Println(record) // 输出: [name;age;city]  错误地将整行视为一个字段

   // 正确的做法是设置分隔符
   r.Comma = ';'
   record, _ = r.Read()
   fmt.Println(record) // 输出: [name age city]
   record, _ = r.Read()
   fmt.Println(record) // 输出: [Alice 30 New York]
   ```

2. **引号处理不当：**  忘记使用引号包围包含分隔符或换行符的字段，或者引号不成对。

   **例如：**

   ```go
   // 假设 CSV 数据为 "name,address\nAlice,Street A, City B"
   csvData := "name,address\nAlice,Street A, City B"
   r := csv.NewReader(strings.NewReader(csvData))
   record, _ := r.Read()
   fmt.Println(record) // 输出: [name address]
   record, _ = r.Read()
   fmt.Println(record) // 输出: [Alice Street A  City B]  地址被错误地分割成多个字段

   // 正确的做法是使用引号
   csvData = "name,address\nAlice,\"Street A, City B\""
   r = csv.NewReader(strings.NewReader(csvData))
   r.Read() // 读取标题行
   record, _ = r.Read()
   fmt.Println(record) // 输出: [Alice Street A, City B]
   ```

3. **假设固定的字段数量但实际不符：** 如果设置了 `FieldsPerRecord` 为正数，但 CSV 文件中某些行的字段数量与该值不符，会导致 `ErrFieldCount` 错误。

   **例如：**

   ```go
   csvData := "name,age\nAlice,30\nBob" // 第二行缺少 age 字段
   r := csv.NewReader(strings.NewReader(csvData))
   r.FieldsPerRecord = 2
   r.Read() // 读取标题行
   _, err := r.Read() // 读取第二行
   fmt.Println(err) // 输出: record on line 3: wrong number of fields
   ```

了解这些功能和潜在的陷阱，可以帮助开发者更有效地使用 Go 语言的 `encoding/csv` 包来处理 CSV 数据。

### 提示词
```
这是路径为go/src/encoding/csv/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package csv reads and writes comma-separated values (CSV) files.
// There are many kinds of CSV files; this package supports the format
// described in RFC 4180, except that [Writer] uses LF
// instead of CRLF as newline character by default.
//
// A csv file contains zero or more records of one or more fields per record.
// Each record is separated by the newline character. The final record may
// optionally be followed by a newline character.
//
//	field1,field2,field3
//
// White space is considered part of a field.
//
// Carriage returns before newline characters are silently removed.
//
// Blank lines are ignored. A line with only whitespace characters (excluding
// the ending newline character) is not considered a blank line.
//
// Fields which start and stop with the quote character " are called
// quoted-fields. The beginning and ending quote are not part of the
// field.
//
// The source:
//
//	normal string,"quoted-field"
//
// results in the fields
//
//	{`normal string`, `quoted-field`}
//
// Within a quoted-field a quote character followed by a second quote
// character is considered a single quote.
//
//	"the ""word"" is true","a ""quoted-field"""
//
// results in
//
//	{`the "word" is true`, `a "quoted-field"`}
//
// Newlines and commas may be included in a quoted-field
//
//	"Multi-line
//	field","comma is ,"
//
// results in
//
//	{`Multi-line
//	field`, `comma is ,`}
package csv

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// A ParseError is returned for parsing errors.
// Line and column numbers are 1-indexed.
type ParseError struct {
	StartLine int   // Line where the record starts
	Line      int   // Line where the error occurred
	Column    int   // Column (1-based byte index) where the error occurred
	Err       error // The actual error
}

func (e *ParseError) Error() string {
	if e.Err == ErrFieldCount {
		return fmt.Sprintf("record on line %d: %v", e.Line, e.Err)
	}
	if e.StartLine != e.Line {
		return fmt.Sprintf("record on line %d; parse error on line %d, column %d: %v", e.StartLine, e.Line, e.Column, e.Err)
	}
	return fmt.Sprintf("parse error on line %d, column %d: %v", e.Line, e.Column, e.Err)
}

func (e *ParseError) Unwrap() error { return e.Err }

// These are the errors that can be returned in [ParseError.Err].
var (
	ErrBareQuote  = errors.New("bare \" in non-quoted-field")
	ErrQuote      = errors.New("extraneous or missing \" in quoted-field")
	ErrFieldCount = errors.New("wrong number of fields")

	// Deprecated: ErrTrailingComma is no longer used.
	ErrTrailingComma = errors.New("extra delimiter at end of line")
)

var errInvalidDelim = errors.New("csv: invalid field or comment delimiter")

func validDelim(r rune) bool {
	return r != 0 && r != '"' && r != '\r' && r != '\n' && utf8.ValidRune(r) && r != utf8.RuneError
}

// A Reader reads records from a CSV-encoded file.
//
// As returned by [NewReader], a Reader expects input conforming to RFC 4180.
// The exported fields can be changed to customize the details before the
// first call to [Reader.Read] or [Reader.ReadAll].
//
// The Reader converts all \r\n sequences in its input to plain \n,
// including in multiline field values, so that the returned data does
// not depend on which line-ending convention an input file uses.
type Reader struct {
	// Comma is the field delimiter.
	// It is set to comma (',') by NewReader.
	// Comma must be a valid rune and must not be \r, \n,
	// or the Unicode replacement character (0xFFFD).
	Comma rune

	// Comment, if not 0, is the comment character. Lines beginning with the
	// Comment character without preceding whitespace are ignored.
	// With leading whitespace the Comment character becomes part of the
	// field, even if TrimLeadingSpace is true.
	// Comment must be a valid rune and must not be \r, \n,
	// or the Unicode replacement character (0xFFFD).
	// It must also not be equal to Comma.
	Comment rune

	// FieldsPerRecord is the number of expected fields per record.
	// If FieldsPerRecord is positive, Read requires each record to
	// have the given number of fields. If FieldsPerRecord is 0, Read sets it to
	// the number of fields in the first record, so that future records must
	// have the same field count. If FieldsPerRecord is negative, no check is
	// made and records may have a variable number of fields.
	FieldsPerRecord int

	// If LazyQuotes is true, a quote may appear in an unquoted field and a
	// non-doubled quote may appear in a quoted field.
	LazyQuotes bool

	// If TrimLeadingSpace is true, leading white space in a field is ignored.
	// This is done even if the field delimiter, Comma, is white space.
	TrimLeadingSpace bool

	// ReuseRecord controls whether calls to Read may return a slice sharing
	// the backing array of the previous call's returned slice for performance.
	// By default, each call to Read returns newly allocated memory owned by the caller.
	ReuseRecord bool

	// Deprecated: TrailingComma is no longer used.
	TrailingComma bool

	r *bufio.Reader

	// numLine is the current line being read in the CSV file.
	numLine int

	// offset is the input stream byte offset of the current reader position.
	offset int64

	// rawBuffer is a line buffer only used by the readLine method.
	rawBuffer []byte

	// recordBuffer holds the unescaped fields, one after another.
	// The fields can be accessed by using the indexes in fieldIndexes.
	// E.g., For the row `a,"b","c""d",e`, recordBuffer will contain `abc"de`
	// and fieldIndexes will contain the indexes [1, 2, 5, 6].
	recordBuffer []byte

	// fieldIndexes is an index of fields inside recordBuffer.
	// The i'th field ends at offset fieldIndexes[i] in recordBuffer.
	fieldIndexes []int

	// fieldPositions is an index of field positions for the
	// last record returned by Read.
	fieldPositions []position

	// lastRecord is a record cache and only used when ReuseRecord == true.
	lastRecord []string
}

// NewReader returns a new Reader that reads from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		Comma: ',',
		r:     bufio.NewReader(r),
	}
}

// Read reads one record (a slice of fields) from r.
// If the record has an unexpected number of fields,
// Read returns the record along with the error [ErrFieldCount].
// If the record contains a field that cannot be parsed,
// Read returns a partial record along with the parse error.
// The partial record contains all fields read before the error.
// If there is no data left to be read, Read returns nil, [io.EOF].
// If [Reader.ReuseRecord] is true, the returned slice may be shared
// between multiple calls to Read.
func (r *Reader) Read() (record []string, err error) {
	if r.ReuseRecord {
		record, err = r.readRecord(r.lastRecord)
		r.lastRecord = record
	} else {
		record, err = r.readRecord(nil)
	}
	return record, err
}

// FieldPos returns the line and column corresponding to
// the start of the field with the given index in the slice most recently
// returned by [Reader.Read]. Numbering of lines and columns starts at 1;
// columns are counted in bytes, not runes.
//
// If this is called with an out-of-bounds index, it panics.
func (r *Reader) FieldPos(field int) (line, column int) {
	if field < 0 || field >= len(r.fieldPositions) {
		panic("out of range index passed to FieldPos")
	}
	p := &r.fieldPositions[field]
	return p.line, p.col
}

// InputOffset returns the input stream byte offset of the current reader
// position. The offset gives the location of the end of the most recently
// read row and the beginning of the next row.
func (r *Reader) InputOffset() int64 {
	return r.offset
}

// pos holds the position of a field in the current line.
type position struct {
	line, col int
}

// ReadAll reads all the remaining records from r.
// Each record is a slice of fields.
// A successful call returns err == nil, not err == [io.EOF]. Because ReadAll is
// defined to read until EOF, it does not treat end of file as an error to be
// reported.
func (r *Reader) ReadAll() (records [][]string, err error) {
	for {
		record, err := r.readRecord(nil)
		if err == io.EOF {
			return records, nil
		}
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
}

// readLine reads the next line (with the trailing endline).
// If EOF is hit without a trailing endline, it will be omitted.
// If some bytes were read, then the error is never [io.EOF].
// The result is only valid until the next call to readLine.
func (r *Reader) readLine() ([]byte, error) {
	line, err := r.r.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		r.rawBuffer = append(r.rawBuffer[:0], line...)
		for err == bufio.ErrBufferFull {
			line, err = r.r.ReadSlice('\n')
			r.rawBuffer = append(r.rawBuffer, line...)
		}
		line = r.rawBuffer
	}
	readSize := len(line)
	if readSize > 0 && err == io.EOF {
		err = nil
		// For backwards compatibility, drop trailing \r before EOF.
		if line[readSize-1] == '\r' {
			line = line[:readSize-1]
		}
	}
	r.numLine++
	r.offset += int64(readSize)
	// Normalize \r\n to \n on all input lines.
	if n := len(line); n >= 2 && line[n-2] == '\r' && line[n-1] == '\n' {
		line[n-2] = '\n'
		line = line[:n-1]
	}
	return line, err
}

// lengthNL reports the number of bytes for the trailing \n.
func lengthNL(b []byte) int {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return 1
	}
	return 0
}

// nextRune returns the next rune in b or utf8.RuneError.
func nextRune(b []byte) rune {
	r, _ := utf8.DecodeRune(b)
	return r
}

func (r *Reader) readRecord(dst []string) ([]string, error) {
	if r.Comma == r.Comment || !validDelim(r.Comma) || (r.Comment != 0 && !validDelim(r.Comment)) {
		return nil, errInvalidDelim
	}

	// Read line (automatically skipping past empty lines and any comments).
	var line []byte
	var errRead error
	for errRead == nil {
		line, errRead = r.readLine()
		if r.Comment != 0 && nextRune(line) == r.Comment {
			line = nil
			continue // Skip comment lines
		}
		if errRead == nil && len(line) == lengthNL(line) {
			line = nil
			continue // Skip empty lines
		}
		break
	}
	if errRead == io.EOF {
		return nil, errRead
	}

	// Parse each field in the record.
	var err error
	const quoteLen = len(`"`)
	commaLen := utf8.RuneLen(r.Comma)
	recLine := r.numLine // Starting line for record
	r.recordBuffer = r.recordBuffer[:0]
	r.fieldIndexes = r.fieldIndexes[:0]
	r.fieldPositions = r.fieldPositions[:0]
	pos := position{line: r.numLine, col: 1}
parseField:
	for {
		if r.TrimLeadingSpace {
			i := bytes.IndexFunc(line, func(r rune) bool {
				return !unicode.IsSpace(r)
			})
			if i < 0 {
				i = len(line)
				pos.col -= lengthNL(line)
			}
			line = line[i:]
			pos.col += i
		}
		if len(line) == 0 || line[0] != '"' {
			// Non-quoted string field
			i := bytes.IndexRune(line, r.Comma)
			field := line
			if i >= 0 {
				field = field[:i]
			} else {
				field = field[:len(field)-lengthNL(field)]
			}
			// Check to make sure a quote does not appear in field.
			if !r.LazyQuotes {
				if j := bytes.IndexByte(field, '"'); j >= 0 {
					col := pos.col + j
					err = &ParseError{StartLine: recLine, Line: r.numLine, Column: col, Err: ErrBareQuote}
					break parseField
				}
			}
			r.recordBuffer = append(r.recordBuffer, field...)
			r.fieldIndexes = append(r.fieldIndexes, len(r.recordBuffer))
			r.fieldPositions = append(r.fieldPositions, pos)
			if i >= 0 {
				line = line[i+commaLen:]
				pos.col += i + commaLen
				continue parseField
			}
			break parseField
		} else {
			// Quoted string field
			fieldPos := pos
			line = line[quoteLen:]
			pos.col += quoteLen
			for {
				i := bytes.IndexByte(line, '"')
				if i >= 0 {
					// Hit next quote.
					r.recordBuffer = append(r.recordBuffer, line[:i]...)
					line = line[i+quoteLen:]
					pos.col += i + quoteLen
					switch rn := nextRune(line); {
					case rn == '"':
						// `""` sequence (append quote).
						r.recordBuffer = append(r.recordBuffer, '"')
						line = line[quoteLen:]
						pos.col += quoteLen
					case rn == r.Comma:
						// `",` sequence (end of field).
						line = line[commaLen:]
						pos.col += commaLen
						r.fieldIndexes = append(r.fieldIndexes, len(r.recordBuffer))
						r.fieldPositions = append(r.fieldPositions, fieldPos)
						continue parseField
					case lengthNL(line) == len(line):
						// `"\n` sequence (end of line).
						r.fieldIndexes = append(r.fieldIndexes, len(r.recordBuffer))
						r.fieldPositions = append(r.fieldPositions, fieldPos)
						break parseField
					case r.LazyQuotes:
						// `"` sequence (bare quote).
						r.recordBuffer = append(r.recordBuffer, '"')
					default:
						// `"*` sequence (invalid non-escaped quote).
						err = &ParseError{StartLine: recLine, Line: r.numLine, Column: pos.col - quoteLen, Err: ErrQuote}
						break parseField
					}
				} else if len(line) > 0 {
					// Hit end of line (copy all data so far).
					r.recordBuffer = append(r.recordBuffer, line...)
					if errRead != nil {
						break parseField
					}
					pos.col += len(line)
					line, errRead = r.readLine()
					if len(line) > 0 {
						pos.line++
						pos.col = 1
					}
					if errRead == io.EOF {
						errRead = nil
					}
				} else {
					// Abrupt end of file (EOF or error).
					if !r.LazyQuotes && errRead == nil {
						err = &ParseError{StartLine: recLine, Line: pos.line, Column: pos.col, Err: ErrQuote}
						break parseField
					}
					r.fieldIndexes = append(r.fieldIndexes, len(r.recordBuffer))
					r.fieldPositions = append(r.fieldPositions, fieldPos)
					break parseField
				}
			}
		}
	}
	if err == nil {
		err = errRead
	}

	// Create a single string and create slices out of it.
	// This pins the memory of the fields together, but allocates once.
	str := string(r.recordBuffer) // Convert to string once to batch allocations
	dst = dst[:0]
	if cap(dst) < len(r.fieldIndexes) {
		dst = make([]string, len(r.fieldIndexes))
	}
	dst = dst[:len(r.fieldIndexes)]
	var preIdx int
	for i, idx := range r.fieldIndexes {
		dst[i] = str[preIdx:idx]
		preIdx = idx
	}

	// Check or update the expected fields per record.
	if r.FieldsPerRecord > 0 {
		if len(dst) != r.FieldsPerRecord && err == nil {
			err = &ParseError{
				StartLine: recLine,
				Line:      recLine,
				Column:    1,
				Err:       ErrFieldCount,
			}
		}
	} else if r.FieldsPerRecord == 0 {
		r.FieldsPerRecord = len(dst)
	}
	return dst, err
}
```