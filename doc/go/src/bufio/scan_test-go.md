Response:
Let's break down the thought process for analyzing the provided Go code snippet for `bufio/scan_test.go`.

1. **Understanding the Context:** The first thing is to recognize the file name: `scan_test.go`. The `_test.go` suffix immediately tells us this is a testing file within the `bufio` package. This means its primary purpose is to test the functionality of the `bufio` package, specifically the `Scanner` type and related functions.

2. **Scanning for Key Components:**  I'll quickly scan through the code looking for:
    * **Imports:**  What other packages are being used? This gives clues about the functionalities being tested. Here, we see `bufio`, `bytes`, `errors`, `io`, `strings`, `testing`, `unicode`, and `unicode/utf8`. These imports suggest testing of byte-level operations, string manipulation, error handling, and Unicode support. The import `. "bufio"` is important, as it means the tests can directly access exported members of the `bufio` package without the `bufio.` prefix.
    * **Test Functions:** Functions starting with `Test`. These are the individual test cases. I'll make a mental note of some of the names like `TestScanByte`, `TestScanRune`, `TestScanWords`, `TestScanLongLines`, etc. These names hint at the specific functionalities being tested.
    * **Helper Functions/Types:** Are there any custom types or functions created specifically for testing?  I see `slowReader`, `genLine`, `countdown`, `negativeEOFReader`, and `largeReader`. These are likely designed to create specific scenarios for testing the `Scanner`.
    * **Global Variables:** Any global variables?  `scanTests` and `wordScanTests` look like data sets used for multiple tests. `smallMaxTokenSize` is a constant used to control the token size in some tests.

3. **Analyzing Individual Test Functions:** Now I'll dive into the details of a few key test functions to understand how they work:

    * **`TestSpace`:** This one is straightforward. It iterates through all possible Unicode runes and checks if `bufio.IsSpace` returns the same result as `unicode.IsSpace`. This confirms the correctness of the whitespace detection in `bufio`.

    * **`TestScanByte`:** This test iterates through the `scanTests` data. For each test string, it creates a `Scanner`, sets the split function to `ScanBytes`, and then iterates through the scanned "tokens" (which should be individual bytes). It verifies that each scanned byte matches the corresponding byte in the original string. This test confirms the `ScanBytes` splitter is working correctly.

    * **`TestScanRune`:**  Similar to `TestScanByte`, but uses `ScanRunes`. It iterates through the runes of the test string using a `range` loop and compares them to the runes extracted by the `Scanner`. This verifies the correct handling of multi-byte UTF-8 characters.

    * **`TestScanWords`:** This test uses `ScanWords` and compares the results to `strings.Fields`. This verifies that the `ScanWords` splitter correctly identifies words separated by whitespace.

    * **`TestScanLongLines` and `TestScanLineTooLong`:** These tests focus on `ScanLines`. `TestScanLongLines` tests the case where lines are within the `MaxTokenSize`, while `TestScanLineTooLong` specifically checks the error handling when a line exceeds this limit. The use of `slowReader` is interesting here, simulating a reader that provides data in small chunks, testing the incremental reading capability of the `Scanner`.

4. **Identifying Core Functionality:** Based on the test functions, I can deduce the primary functionalities being tested:
    * **Splitting Input:**  The `Scanner` allows splitting input into tokens based on different criteria (bytes, runes, words, lines, custom delimiters). This is evident from the `Split` method and the different `Scan...` functions being tested.
    * **Scanning:** The `Scan` method advances the scanner to the next token.
    * **Accessing Tokens:** The `Bytes()` and `Text()` methods are used to retrieve the scanned token as a byte slice or a string.
    * **Error Handling:** The `Err()` method is used to check for errors during scanning, including `io.EOF` and `ErrTooLong`.
    * **Custom Splitters:** The code demonstrates the ability to define custom splitting logic using a function with the `SplitFunc` signature.
    * **Maximum Token Size:** The `MaxTokenSize` method allows controlling the maximum size of a scanned token.
    * **Buffering:** The `Buffer` method allows customizing the initial and maximum buffer size.

5. **Constructing Examples:** Now I can start constructing Go code examples to illustrate the identified functionalities. This involves showing how to create a `Scanner`, set the splitter, use `Scan`, and access the token.

6. **Inferring Go Language Features:**  The code heavily uses the `bufio.Scanner`, which is designed for efficient reading of input streams. The use of interfaces like `io.Reader` is also prominent. The concept of a "splitter" function as a first-class citizen in Go is also highlighted.

7. **Considering Edge Cases and Potential Errors:**  The tests themselves point to potential pitfalls. For instance, `TestScanLineTooLong` highlights the issue of exceeding the maximum token size. The tests involving `slowReader` implicitly suggest that users might encounter issues if the underlying reader is slow or has unexpected behavior. The `TestDontLoopForever` test hints at a potential issue with custom splitters that might return empty tokens indefinitely.

8. **Structuring the Answer:** Finally, I organize the findings into a coherent answer, covering the functionalities, providing code examples, explaining the underlying Go features, discussing potential errors, and addressing each part of the original prompt. I make sure to use clear and concise Chinese. I review the answer to ensure it directly addresses the prompt and is easy to understand.
这段代码是 Go 语言标准库 `bufio` 包中 `scan_test.go` 文件的一部分，它的主要功能是**测试 `bufio` 包中的 `Scanner` 类型及其相关的分词 (splitting) 功能**。

具体来说，它测试了 `Scanner` 的以下几个核心功能：

1. **空格判断 (`TestSpace`)**:  验证 `bufio.IsSpace` 函数的行为是否与 `unicode.IsSpace` 一致，确保 `bufio` 包对 Unicode 空格的定义是正确的。

2. **基于不同规则的分词 (`TestScanByte`, `TestScanRune`, `TestScanWords`, `TestScanLongLines`)**:
   - **`ScanBytes`**: 将输入流的每个字节作为一个独立的 token。
   - **`ScanRunes`**: 将输入流的每个 Unicode 字符 (rune) 作为一个独立的 token。
   - **`ScanWords`**: 将输入流的每个单词作为一个独立的 token，单词之间由空白符分隔。
   - **`ScanLines`**: 将输入流的每一行作为一个独立的 token，行尾由换行符 (`\n`) 或回车换行符 (`\r\n`) 标识。

3. **处理不同类型的输入 (`scanTests`, `wordScanTests`)**:  使用各种不同的字符串作为输入，包括空字符串、单字符、多字符、包含特殊字符、包含 UTF-8 字符、包含错误 UTF-8 编码的字符串等，以覆盖不同的输入场景。

4. **处理长行和 `MaxTokenSize` (`TestScanLongLines`, `TestScanLineTooLong`)**:  测试 `ScanLines` 在处理长行时的行为。 `Scanner` 有一个 `MaxTokenSize` 限制，当一行超过这个限制时，会返回 `ErrTooLong` 错误。

5. **处理没有换行符的最后一行 (`TestScanLineNoNewline`, `TestScanLineReturnButNoNewline`)**: 确保 `ScanLines` 能正确处理输入流末尾没有换行符的情况。

6. **处理空行 (`TestScanLineEmptyFinalLine`, `TestScanLineEmptyFinalLineWithCR`)**: 验证 `ScanLines` 能正确处理输入流中的空行。

7. **处理自定义分词函数 (`TestSplitError`, `TestErrAtEOF`, `TestEmptyTokens`, `TestDontLoopForever`, `TestEmptyLinesOK`)**:  `Scanner` 允许用户自定义分词函数 (`SplitFunc`)。这些测试验证了自定义分词函数的正确性，包括错误处理、EOF 处理以及处理空 token 的情况。

8. **处理读取错误 (`TestNonEOFWithEmptyRead`, `TestBadReader`, `TestNegativeEOFReader`, `TestLargeReader`)**:  测试当底层的 `io.Reader` 返回错误时的 `Scanner` 行为，例如 `io.ErrUnexpectedEOF` 或始终返回 0 字节的情况。

9. **设置和使用缓冲区 (`TestHugeBuffer`)**:  测试 `Scanner` 的 `Buffer` 方法，允许用户自定义内部缓冲区的大小，以处理非常大的 token。

**推理 `bufio.Scanner` 的功能及 Go 代码举例说明:**

`bufio.Scanner` 的主要功能是提供一种方便且高效的方式来读取输入流（实现了 `io.Reader` 接口）并将其分割成多个 token。 用户可以自定义如何分割输入流。

**假设输入:**  一个包含多行文本的文件，我们想逐行读取并处理。

```go
package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	file, err := os.Open("example.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// 使用默认的 ScanLines 分词函数，按行读取
	for scanner.Scan() {
		line := scanner.Text() // 获取当前行的文本
		fmt.Println(line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("读取文件时发生错误:", err)
	}
}
```

**假设 `example.txt` 的内容如下:**

```
第一行内容
这是第二行
第三行，包含一些特殊字符 !@#$%^
```

**预期输出:**

```
第一行内容
这是第二行
第三行，包含一些特殊字符 !@#$%^
```

**代码解释:**

1. `bufio.NewScanner(file)`: 创建一个新的 `Scanner`，它从 `file` 中读取数据。
2. `scanner.Scan()`: 尝试读取下一个 token（在本例中是一行）。如果读取成功，返回 `true`，否则返回 `false`（通常是到达文件末尾）。
3. `scanner.Text()`: 返回最近一次 `Scan` 读取到的 token 的字符串表示。
4. `scanner.Err()`: 如果在扫描过程中发生错误，返回该错误。通常在 `scanner.Scan()` 返回 `false` 后调用，以区分是到达文件末尾还是发生了错误。

**涉及代码推理的例子 (自定义分词函数):**

**假设输入:** 一个逗号分隔的字符串 "apple,banana,orange,grape"。我们想按逗号分割并获取每个水果名称。

```go
package main

import (
	"bufio"
	"fmt"
	"strings"
)

func main() {
	input := "apple,banana,orange,grape"
	reader := strings.NewReader(input)
	scanner := bufio.NewScanner(reader)

	// 自定义分词函数
	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		for i := 0; i < len(data); i++ {
			if data[i] == ',' {
				return i + 1, data[:i], nil // 返回 token 和前进的字节数
			}
		}
		if atEOF && len(data) > 0 {
			return len(data), data, bufio.ErrFinalToken // 处理最后一个 token
		}
		return 0, nil, nil // 需要更多数据
	}

	scanner.Split(split) // 设置自定义分词函数

	for scanner.Scan() {
		fruit := scanner.Text()
		fmt.Println(fruit)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("扫描时发生错误:", err)
	}
}
```

**预期输出:**

```
apple
banana
orange
grape
```

**代码解释:**

1. 我们定义了一个名为 `split` 的函数，它符合 `bufio.SplitFunc` 的签名。
2. `split` 函数遍历输入数据，找到逗号，并返回逗号前的部分作为 token。
3. `scanner.Split(split)` 将这个自定义的分词函数设置给 `scanner`。
4. `scanner.Scan()` 和 `scanner.Text()` 按照自定义的规则提取 token。

**涉及命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它的目的是测试 `bufio.Scanner` 的功能，通常它会读取预定义的字符串或模拟的 `io.Reader`。如果涉及到从命令行读取输入并使用 `bufio.Scanner`，你需要在你的主程序中处理命令行参数，例如使用 `os.Args` 或 `flag` 包，并将读取到的内容传递给 `bufio.Scanner`。

**使用者易犯错的点:**

1. **忘记检查 `scanner.Err()`:**  `scanner.Scan()` 在遇到错误或到达文件末尾时都会返回 `false`。仅仅检查 `scanner.Scan()` 的返回值是不够的，还需要检查 `scanner.Err()` 以区分是正常结束还是发生了错误。

    ```go
    scanner := bufio.NewScanner(reader)
    for scanner.Scan() {
        // 处理扫描到的内容
    }
    if err := scanner.Err(); err != nil { // 必须检查错误
        fmt.Println("Error during scanning:", err)
    }
    ```

2. **`MaxTokenSize` 的限制:**  默认情况下，`Scanner` 有一个 `MaxScanTokenSize` 的限制。如果读取到的 token 超过这个限制（例如，使用 `ScanLines` 时一行过长），`scanner.Scan()` 会返回 `false`，并且 `scanner.Err()` 会返回 `bufio.ErrTooLong`。使用者需要注意这个限制，或者使用 `scanner.Buffer()` 方法来增加缓冲区的容量，或者自定义分词逻辑来处理超长 token。

    ```go
    scanner := bufio.NewScanner(reader)
    // 假设我们知道可能会有很长的行
    buf := make([]byte, bufio.MaxScanTokenSize)
    scanner.Buffer(buf, bufio.MaxScanTokenSize*2) // 增大缓冲区

    for scanner.Scan() {
        // ...
    }
    if err := scanner.Err(); err != nil {
        fmt.Println("Error during scanning:", err)
    }
    ```

3. **自定义 `SplitFunc` 的逻辑错误:**  自定义 `SplitFunc` 需要非常小心，确保它正确地返回 `advance` (已处理的字节数) 和 `token`。如果 `advance` 返回不正确，可能会导致无限循环或遗漏数据。例如，如果始终返回 `0` 作为 `advance`，`Scanner` 会认为没有取得进展，可能导致 panic。测试代码中的 `TestDontLoopForever` 就是为了检测这种情况。

4. **对 `scanner.Bytes()` 和 `scanner.Text()` 的误解:** `scanner.Bytes()` 返回的是 `Scanner` 内部缓冲区的切片，这个切片可能会在下一次 `scanner.Scan()` 调用时被覆盖。如果需要在多次迭代中使用 token 的内容，应该复制其值。`scanner.Text()` 返回的是 token 的字符串副本，相对安全一些。

    ```go
    scanner := bufio.NewScanner(reader)
    for scanner.Scan() {
        bytes := scanner.Bytes()
        // time.Sleep(time.Second) // 模拟一些操作
        // 此时 bytes 的内容可能已经被修改，如果下一次 Scan 发生了
        text := string(bytes) // 正确的做法是复制一份
        fmt.Println(text)
    }
    ```

总而言之，这段测试代码全面地验证了 `bufio.Scanner` 的各种功能和边界情况，帮助开发者理解和正确使用这个强大的输入处理工具。

### 提示词
```
这是路径为go/src/bufio/scan_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bufio_test

import (
	. "bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const smallMaxTokenSize = 256 // Much smaller for more efficient testing.

// Test white space table matches the Unicode definition.
func TestSpace(t *testing.T) {
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if IsSpace(r) != unicode.IsSpace(r) {
			t.Fatalf("white space property disagrees: %#U should be %t", r, unicode.IsSpace(r))
		}
	}
}

var scanTests = []string{
	"",
	"a",
	"¼",
	"☹",
	"\x81",   // UTF-8 error
	"\uFFFD", // correctly encoded RuneError
	"abcdefgh",
	"abc def\n\t\tgh    ",
	"abc¼☹\x81\uFFFD日本語\x82abc",
}

func TestScanByte(t *testing.T) {
	for n, test := range scanTests {
		buf := strings.NewReader(test)
		s := NewScanner(buf)
		s.Split(ScanBytes)
		var i int
		for i = 0; s.Scan(); i++ {
			if b := s.Bytes(); len(b) != 1 || b[0] != test[i] {
				t.Errorf("#%d: %d: expected %q got %q", n, i, test, b)
			}
		}
		if i != len(test) {
			t.Errorf("#%d: termination expected at %d; got %d", n, len(test), i)
		}
		err := s.Err()
		if err != nil {
			t.Errorf("#%d: %v", n, err)
		}
	}
}

// Test that the rune splitter returns same sequence of runes (not bytes) as for range string.
func TestScanRune(t *testing.T) {
	for n, test := range scanTests {
		buf := strings.NewReader(test)
		s := NewScanner(buf)
		s.Split(ScanRunes)
		var i, runeCount int
		var expect rune
		// Use a string range loop to validate the sequence of runes.
		for i, expect = range test {
			if !s.Scan() {
				break
			}
			runeCount++
			got, _ := utf8.DecodeRune(s.Bytes())
			if got != expect {
				t.Errorf("#%d: %d: expected %q got %q", n, i, expect, got)
			}
		}
		if s.Scan() {
			t.Errorf("#%d: scan ran too long, got %q", n, s.Text())
		}
		testRuneCount := utf8.RuneCountInString(test)
		if runeCount != testRuneCount {
			t.Errorf("#%d: termination expected at %d; got %d", n, testRuneCount, runeCount)
		}
		err := s.Err()
		if err != nil {
			t.Errorf("#%d: %v", n, err)
		}
	}
}

var wordScanTests = []string{
	"",
	" ",
	"\n",
	"a",
	" a ",
	"abc def",
	" abc def ",
	" abc\tdef\nghi\rjkl\fmno\vpqr\u0085stu\u00a0\n",
}

// Test that the word splitter returns the same data as strings.Fields.
func TestScanWords(t *testing.T) {
	for n, test := range wordScanTests {
		buf := strings.NewReader(test)
		s := NewScanner(buf)
		s.Split(ScanWords)
		words := strings.Fields(test)
		var wordCount int
		for wordCount = 0; wordCount < len(words); wordCount++ {
			if !s.Scan() {
				break
			}
			got := s.Text()
			if got != words[wordCount] {
				t.Errorf("#%d: %d: expected %q got %q", n, wordCount, words[wordCount], got)
			}
		}
		if s.Scan() {
			t.Errorf("#%d: scan ran too long, got %q", n, s.Text())
		}
		if wordCount != len(words) {
			t.Errorf("#%d: termination expected at %d; got %d", n, len(words), wordCount)
		}
		err := s.Err()
		if err != nil {
			t.Errorf("#%d: %v", n, err)
		}
	}
}

// slowReader is a reader that returns only a few bytes at a time, to test the incremental
// reads in Scanner.Scan.
type slowReader struct {
	max int
	buf io.Reader
}

func (sr *slowReader) Read(p []byte) (n int, err error) {
	if len(p) > sr.max {
		p = p[0:sr.max]
	}
	return sr.buf.Read(p)
}

// genLine writes to buf a predictable but non-trivial line of text of length
// n, including the terminal newline and an occasional carriage return.
// If addNewline is false, the \r and \n are not emitted.
func genLine(buf *bytes.Buffer, lineNum, n int, addNewline bool) {
	buf.Reset()
	doCR := lineNum%5 == 0
	if doCR {
		n--
	}
	for i := 0; i < n-1; i++ { // Stop early for \n.
		c := 'a' + byte(lineNum+i)
		if c == '\n' || c == '\r' { // Don't confuse us.
			c = 'N'
		}
		buf.WriteByte(c)
	}
	if addNewline {
		if doCR {
			buf.WriteByte('\r')
		}
		buf.WriteByte('\n')
	}
}

// Test the line splitter, including some carriage returns but no long lines.
func TestScanLongLines(t *testing.T) {
	// Build a buffer of lots of line lengths up to but not exceeding smallMaxTokenSize.
	tmp := new(bytes.Buffer)
	buf := new(bytes.Buffer)
	lineNum := 0
	j := 0
	for i := 0; i < 2*smallMaxTokenSize; i++ {
		genLine(tmp, lineNum, j, true)
		if j < smallMaxTokenSize {
			j++
		} else {
			j--
		}
		buf.Write(tmp.Bytes())
		lineNum++
	}
	s := NewScanner(&slowReader{1, buf})
	s.Split(ScanLines)
	s.MaxTokenSize(smallMaxTokenSize)
	j = 0
	for lineNum := 0; s.Scan(); lineNum++ {
		genLine(tmp, lineNum, j, false)
		if j < smallMaxTokenSize {
			j++
		} else {
			j--
		}
		line := tmp.String() // We use the string-valued token here, for variety.
		if s.Text() != line {
			t.Errorf("%d: bad line: %d %d\n%.100q\n%.100q\n", lineNum, len(s.Bytes()), len(line), s.Text(), line)
		}
	}
	err := s.Err()
	if err != nil {
		t.Fatal(err)
	}
}

// Test that the line splitter errors out on a long line.
func TestScanLineTooLong(t *testing.T) {
	const smallMaxTokenSize = 256 // Much smaller for more efficient testing.
	// Build a buffer of lots of line lengths up to but not exceeding smallMaxTokenSize.
	tmp := new(bytes.Buffer)
	buf := new(bytes.Buffer)
	lineNum := 0
	j := 0
	for i := 0; i < 2*smallMaxTokenSize; i++ {
		genLine(tmp, lineNum, j, true)
		j++
		buf.Write(tmp.Bytes())
		lineNum++
	}
	s := NewScanner(&slowReader{3, buf})
	s.Split(ScanLines)
	s.MaxTokenSize(smallMaxTokenSize)
	j = 0
	for lineNum := 0; s.Scan(); lineNum++ {
		genLine(tmp, lineNum, j, false)
		if j < smallMaxTokenSize {
			j++
		} else {
			j--
		}
		line := tmp.Bytes()
		if !bytes.Equal(s.Bytes(), line) {
			t.Errorf("%d: bad line: %d %d\n%.100q\n%.100q\n", lineNum, len(s.Bytes()), len(line), s.Bytes(), line)
		}
	}
	err := s.Err()
	if err != ErrTooLong {
		t.Fatalf("expected ErrTooLong; got %s", err)
	}
}

// Test that the line splitter handles a final line without a newline.
func testNoNewline(text string, lines []string, t *testing.T) {
	buf := strings.NewReader(text)
	s := NewScanner(&slowReader{7, buf})
	s.Split(ScanLines)
	for lineNum := 0; s.Scan(); lineNum++ {
		line := lines[lineNum]
		if s.Text() != line {
			t.Errorf("%d: bad line: %d %d\n%.100q\n%.100q\n", lineNum, len(s.Bytes()), len(line), s.Bytes(), line)
		}
	}
	err := s.Err()
	if err != nil {
		t.Fatal(err)
	}
}

// Test that the line splitter handles a final line without a newline.
func TestScanLineNoNewline(t *testing.T) {
	const text = "abcdefghijklmn\nopqrstuvwxyz"
	lines := []string{
		"abcdefghijklmn",
		"opqrstuvwxyz",
	}
	testNoNewline(text, lines, t)
}

// Test that the line splitter handles a final line with a carriage return but no newline.
func TestScanLineReturnButNoNewline(t *testing.T) {
	const text = "abcdefghijklmn\nopqrstuvwxyz\r"
	lines := []string{
		"abcdefghijklmn",
		"opqrstuvwxyz",
	}
	testNoNewline(text, lines, t)
}

// Test that the line splitter handles a final empty line.
func TestScanLineEmptyFinalLine(t *testing.T) {
	const text = "abcdefghijklmn\nopqrstuvwxyz\n\n"
	lines := []string{
		"abcdefghijklmn",
		"opqrstuvwxyz",
		"",
	}
	testNoNewline(text, lines, t)
}

// Test that the line splitter handles a final empty line with a carriage return but no newline.
func TestScanLineEmptyFinalLineWithCR(t *testing.T) {
	const text = "abcdefghijklmn\nopqrstuvwxyz\n\r"
	lines := []string{
		"abcdefghijklmn",
		"opqrstuvwxyz",
		"",
	}
	testNoNewline(text, lines, t)
}

var testError = errors.New("testError")

// Test the correct error is returned when the split function errors out.
func TestSplitError(t *testing.T) {
	// Create a split function that delivers a little data, then a predictable error.
	numSplits := 0
	const okCount = 7
	errorSplit := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF {
			panic("didn't get enough data")
		}
		if numSplits >= okCount {
			return 0, nil, testError
		}
		numSplits++
		return 1, data[0:1], nil
	}
	// Read the data.
	const text = "abcdefghijklmnopqrstuvwxyz"
	buf := strings.NewReader(text)
	s := NewScanner(&slowReader{1, buf})
	s.Split(errorSplit)
	var i int
	for i = 0; s.Scan(); i++ {
		if len(s.Bytes()) != 1 || text[i] != s.Bytes()[0] {
			t.Errorf("#%d: expected %q got %q", i, text[i], s.Bytes()[0])
		}
	}
	// Check correct termination location and error.
	if i != okCount {
		t.Errorf("unexpected termination; expected %d tokens got %d", okCount, i)
	}
	err := s.Err()
	if err != testError {
		t.Fatalf("expected %q got %v", testError, err)
	}
}

// Test that an EOF is overridden by a user-generated scan error.
func TestErrAtEOF(t *testing.T) {
	s := NewScanner(strings.NewReader("1 2 33"))
	// This splitter will fail on last entry, after s.err==EOF.
	split := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		advance, token, err = ScanWords(data, atEOF)
		if len(token) > 1 {
			if s.ErrOrEOF() != io.EOF {
				t.Fatal("not testing EOF")
			}
			err = testError
		}
		return
	}
	s.Split(split)
	for s.Scan() {
	}
	if s.Err() != testError {
		t.Fatal("wrong error:", s.Err())
	}
}

// Test for issue 5268.
type alwaysError struct{}

func (alwaysError) Read(p []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestNonEOFWithEmptyRead(t *testing.T) {
	scanner := NewScanner(alwaysError{})
	for scanner.Scan() {
		t.Fatal("read should fail")
	}
	err := scanner.Err()
	if err != io.ErrUnexpectedEOF {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test that Scan finishes if we have endless empty reads.
type endlessZeros struct{}

func (endlessZeros) Read(p []byte) (int, error) {
	return 0, nil
}

func TestBadReader(t *testing.T) {
	scanner := NewScanner(endlessZeros{})
	for scanner.Scan() {
		t.Fatal("read should fail")
	}
	err := scanner.Err()
	if err != io.ErrNoProgress {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanWordsExcessiveWhiteSpace(t *testing.T) {
	const word = "ipsum"
	s := strings.Repeat(" ", 4*smallMaxTokenSize) + word
	scanner := NewScanner(strings.NewReader(s))
	scanner.MaxTokenSize(smallMaxTokenSize)
	scanner.Split(ScanWords)
	if !scanner.Scan() {
		t.Fatalf("scan failed: %v", scanner.Err())
	}
	if token := scanner.Text(); token != word {
		t.Fatalf("unexpected token: %v", token)
	}
}

// Test that empty tokens, including at end of line or end of file, are found by the scanner.
// Issue 8672: Could miss final empty token.

func commaSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for i := 0; i < len(data); i++ {
		if data[i] == ',' {
			return i + 1, data[:i], nil
		}
	}
	return 0, data, ErrFinalToken
}

func testEmptyTokens(t *testing.T, text string, values []string) {
	s := NewScanner(strings.NewReader(text))
	s.Split(commaSplit)
	var i int
	for i = 0; s.Scan(); i++ {
		if i >= len(values) {
			t.Fatalf("got %d fields, expected %d", i+1, len(values))
		}
		if s.Text() != values[i] {
			t.Errorf("%d: expected %q got %q", i, values[i], s.Text())
		}
	}
	if i != len(values) {
		t.Fatalf("got %d fields, expected %d", i, len(values))
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyTokens(t *testing.T) {
	testEmptyTokens(t, "1,2,3,", []string{"1", "2", "3", ""})
}

func TestWithNoEmptyTokens(t *testing.T) {
	testEmptyTokens(t, "1,2,3", []string{"1", "2", "3"})
}

func loopAtEOFSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) > 0 {
		return 1, data[:1], nil
	}
	return 0, data, nil
}

func TestDontLoopForever(t *testing.T) {
	s := NewScanner(strings.NewReader("abc"))
	s.Split(loopAtEOFSplit)
	// Expect a panic
	defer func() {
		err := recover()
		if err == nil {
			t.Fatal("should have panicked")
		}
		if msg, ok := err.(string); !ok || !strings.Contains(msg, "empty tokens") {
			panic(err)
		}
	}()
	for count := 0; s.Scan(); count++ {
		if count > 1000 {
			t.Fatal("looping")
		}
	}
	if s.Err() != nil {
		t.Fatal("after scan:", s.Err())
	}
}

func TestBlankLines(t *testing.T) {
	s := NewScanner(strings.NewReader(strings.Repeat("\n", 1000)))
	for count := 0; s.Scan(); count++ {
		if count > 2000 {
			t.Fatal("looping")
		}
	}
	if s.Err() != nil {
		t.Fatal("after scan:", s.Err())
	}
}

type countdown int

func (c *countdown) split(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if *c > 0 {
		*c--
		return 1, data[:1], nil
	}
	return 0, nil, nil
}

// Check that the looping-at-EOF check doesn't trigger for merely empty tokens.
func TestEmptyLinesOK(t *testing.T) {
	c := countdown(10000)
	s := NewScanner(strings.NewReader(strings.Repeat("\n", 10000)))
	s.Split(c.split)
	for s.Scan() {
	}
	if s.Err() != nil {
		t.Fatal("after scan:", s.Err())
	}
	if c != 0 {
		t.Fatalf("stopped with %d left to process", c)
	}
}

// Make sure we can read a huge token if a big enough buffer is provided.
func TestHugeBuffer(t *testing.T) {
	text := strings.Repeat("x", 2*MaxScanTokenSize)
	s := NewScanner(strings.NewReader(text + "\n"))
	s.Buffer(make([]byte, 100), 3*MaxScanTokenSize)
	for s.Scan() {
		token := s.Text()
		if token != text {
			t.Errorf("scan got incorrect token of length %d", len(token))
		}
	}
	if s.Err() != nil {
		t.Fatal("after scan:", s.Err())
	}
}

// negativeEOFReader returns an invalid -1 at the end, as though it
// were wrapping the read system call.
type negativeEOFReader int

func (r *negativeEOFReader) Read(p []byte) (int, error) {
	if *r > 0 {
		c := int(*r)
		if c > len(p) {
			c = len(p)
		}
		for i := 0; i < c; i++ {
			p[i] = 'a'
		}
		p[c-1] = '\n'
		*r -= negativeEOFReader(c)
		return c, nil
	}
	return -1, io.EOF
}

// Test that the scanner doesn't panic and returns ErrBadReadCount
// on a reader that returns a negative count of bytes read (issue 38053).
func TestNegativeEOFReader(t *testing.T) {
	r := negativeEOFReader(10)
	scanner := NewScanner(&r)
	c := 0
	for scanner.Scan() {
		c++
		if c > 1 {
			t.Error("read too many lines")
			break
		}
	}
	if got, want := scanner.Err(), ErrBadReadCount; got != want {
		t.Errorf("scanner.Err: got %v, want %v", got, want)
	}
}

// largeReader returns an invalid count that is larger than the number
// of bytes requested.
type largeReader struct{}

func (largeReader) Read(p []byte) (int, error) {
	return len(p) + 1, nil
}

// Test that the scanner doesn't panic and returns ErrBadReadCount
// on a reader that returns an impossibly large count of bytes read (issue 38053).
func TestLargeReader(t *testing.T) {
	scanner := NewScanner(largeReader{})
	for scanner.Scan() {
	}
	if got, want := scanner.Err(), ErrBadReadCount; got != want {
		t.Errorf("scanner.Err: got %v, want %v", got, want)
	}
}
```