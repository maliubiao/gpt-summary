Response:
我的思考过程如下：

1. **理解核心功能：** 首先阅读 `Scanner` 类型的注释，明确它的主要目的是为了方便地从 `io.Reader` 中读取数据并将其分割成“token”。  关键词是 "tokens" 和 "split function"。

2. **识别关键组成部分：**  浏览 `Scanner` 结构体的字段，理解每个字段的作用：
    * `r`:  数据来源（`io.Reader`）。
    * `split`:  定义如何分割数据的函数 (`SplitFunc`)。
    * `maxTokenSize`:  单个 token 的最大长度。
    * `token`:  最近一次扫描到的 token。
    * `buf`:  内部缓冲区。
    * `start`, `end`:  缓冲区中数据的起始和结束位置。
    * `err`:  记录遇到的错误。
    * `empties`:  连续空 token 的计数。
    * `scanCalled`, `done`:  状态标记。

3. **分析主要方法：**  重点关注 `NewScanner` 和 `Scan` 方法：
    * `NewScanner`:  创建 `Scanner` 实例，并设置默认的分割函数 (`ScanLines`)。
    * `Scan`:  核心方法，负责读取数据、调用分割函数、返回 token。

4. **深入 `SplitFunc`：**  仔细阅读 `SplitFunc` 的注释，理解其输入参数 (`data`, `atEOF`) 和返回值 (`advance`, `token`, `err`) 的含义。 特别注意 `ErrFinalToken` 的作用。

5. **列举功能点：**  基于以上理解，整理出 `Scanner` 的主要功能：
    * 从 `io.Reader` 读取数据。
    * 根据 `SplitFunc` 将数据分割成 token。
    * 提供了几种内置的 `SplitFunc` (`ScanLines`, `ScanBytes`, `ScanRunes`, `ScanWords`)。
    * 允许自定义 `SplitFunc`。
    * 可以设置最大 token 大小。
    * 提供了获取当前 token 的方法 (`Bytes`, `Text`)。
    * 可以获取扫描过程中遇到的错误 (`Err`)。
    * 提供了 `Buffer` 方法来控制内部缓冲区。

6. **推理 Go 语言功能：**  `bufio.Scanner` 明显是为了方便文本处理而设计的，特别是按行、按单词等分割文本的场景。 这与 Go 语言处理文本数据的能力相符。

7. **编写示例代码：**  选择最常用的按行读取的场景，编写一个使用 `ScanLines` 的例子。 包括：
    * 创建 `strings.Reader` 作为输入。
    * 使用 `NewScanner` 创建 `Scanner`。
    * 使用 `for s.Scan()` 循环读取每一行。
    * 使用 `s.Text()` 获取当前行的内容。
    * 使用 `s.Err()` 检查错误。

8. **推理代码行为（带假设输入输出）：**  针对示例代码，设定一个包含多行文本的输入字符串，并预测程序的输出。

9. **分析命令行参数处理：**  阅读代码后发现 `Scanner` 本身并不直接处理命令行参数。 它只负责读取 `io.Reader` 的数据。  需要明确指出这一点。

10. **识别易犯错误点：**  思考使用 `Scanner` 时可能出现的问题：
    * **未检查错误：**  `Scan()` 返回 `false` 时，需要检查 `Err()`。
    * **大 token 导致 panic：**  默认或设置不当的最大 token 大小可能导致 panic。
    * **自定义 `SplitFunc` 的逻辑错误：**  例如，`advance` 返回值不正确可能导致问题。

11. **组织答案：**  将以上分析结果组织成结构清晰的中文答案，包括功能列表、Go 代码示例、代码推理、命令行参数处理和易犯错误点。  使用 Markdown 格式进行排版，使答案更易读。

12. **Review and Refine:**  最后，重新审视答案，确保准确性和完整性，并对语言进行润色。 例如，最初我可能只关注了 `ScanLines`，但后来意识到 `Scanner` 的灵活性在于其可定制的 `SplitFunc`，因此需要更全面地描述其功能。  对于易犯错误点，最初可能只想到忘记检查错误，但后来补充了大 token 的问题。

通过以上思考过程，我能够逐步理解 `bufio.Scanner` 的功能和使用方法，并生成较为完善的答案。

这段 `go/src/bufio/scan.go` 文件定义了 `bufio` 包中的 `Scanner` 类型，它提供了一种方便的方式来从 `io.Reader` 中读取数据，并按照指定的分隔规则将其分割成一个个的“token”。

以下是 `Scanner` 的主要功能：

1. **从 `io.Reader` 读取数据:** `Scanner` 接收一个 `io.Reader` 作为输入源，例如文件、网络连接或字符串。

2. **定义分割规则 (`SplitFunc`):**  `Scanner` 的核心在于其 `SplitFunc`。这个函数决定了如何将输入的数据分割成 token。 `bufio` 包提供了几个预定义的 `SplitFunc`，包括：
    * **`ScanLines`:** 将输入分割成行，去除行尾的换行符 (`\n` 或 `\r\n`)。这是默认的分割函数。
    * **`ScanBytes`:** 将输入分割成单个字节。
    * **`ScanRunes`:** 将输入分割成 UTF-8 编码的 Unicode 码点 (rune)。
    * **`ScanWords`:** 将输入分割成由空格分隔的单词。
    用户也可以提供自定义的 `SplitFunc` 来实现更复杂的分割逻辑。

3. **逐个读取 Token (`Scan` 方法):**  `Scanner` 的 `Scan()` 方法会读取输入数据，并使用 `SplitFunc` 找到下一个 token。  `Scan()` 返回 `true` 如果找到了一个 token，否则返回 `false`（通常表示到达了输入末尾或遇到了错误）。

4. **获取 Token 内容 (`Bytes` 和 `Text` 方法):**
    * `Bytes()` 方法返回最近一次 `Scan()` 找到的 token 的字节切片。 注意，返回的切片可能指向内部缓冲区，后续的 `Scan()` 调用可能会覆盖这些数据。
    * `Text()` 方法返回最近一次 `Scan()` 找到的 token 的字符串副本。

5. **错误处理 (`Err` 方法):** `Err()` 方法返回在扫描过程中遇到的第一个非 `io.EOF` 类型的错误。如果扫描正常结束（到达输入末尾），`Err()` 返回 `nil`。

6. **自定义缓冲区和最大 Token 大小 (`Buffer` 方法):**  `Buffer()` 方法允许用户提供一个初始缓冲区，并设置在扫描过程中可以分配的最大缓冲区大小。这可以用于优化性能或处理非常大的 token。

7. **自定义分割函数 (`Split` 方法):** `Split()` 方法允许用户在扫描开始前设置自定义的分割函数。

**推理 `Scanner` 是什么 Go 语言功能的实现：**

`bufio.Scanner` 是 Go 语言标准库中用于 **高效读取结构化文本数据** 的实现。它特别适用于处理按行、按单词或其他规则分隔的文本数据，例如读取日志文件、配置文件或网络数据流。  它避免了一次性将整个文件加载到内存中，从而提高了效率并降低了内存消耗。

**Go 代码示例：按行读取文件**

假设我们有一个名为 `data.txt` 的文件，内容如下：

```
This is the first line.
This is the second line.
And this is the third.
```

以下代码演示了如何使用 `bufio.Scanner` 按行读取该文件：

```go
package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	file, err := os.Open("data.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// 假设输入文件 data.txt 内容如上

	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error during scanning:", err)
	}
}
```

**假设的输入与输出：**

**输入 (data.txt):**
```
This is the first line.
This is the second line.
And this is the third.
```

**输出:**
```
This is the first line.
This is the second line.
And this is the third.
```

**Go 代码示例：按空格分割字符串**

```go
package main

import (
	"bufio"
	"fmt"
	"strings"
)

func main() {
	input := "This is a sample string"
	reader := strings.NewReader(input)
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanWords) // 设置分割函数为按空格分割

	// 假设输入字符串为 "This is a sample string"

	for scanner.Scan() {
		word := scanner.Text()
		fmt.Println(word)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error during scanning:", err)
	}
}
```

**假设的输入与输出：**

**输入 (input string):** `"This is a sample string"`

**输出:**
```
This
is
a
sample
string
```

**命令行参数的具体处理：**

`bufio.Scanner` 本身并不直接处理命令行参数。它的作用是从一个 `io.Reader` 中读取数据并进行分割。如果需要从命令行读取输入，通常会使用 `os.Stdin` 作为 `io.Reader` 传递给 `NewScanner`。

例如：

```go
package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin) // 从标准输入读取

	fmt.Println("请输入一些文本，每行一个：")

	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println("你输入了:", line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("读取输入时发生错误:", err)
	}
}
```

在这个例子中，程序会等待用户在命令行输入文本，每输入一行，程序就会将其打印出来。

**使用者易犯错的点：**

1. **未检查 `scanner.Err()`:**  即使 `scanner.Scan()` 返回 `false`，也并不一定意味着到达了文件末尾。可能发生了 I/O 错误或其他错误。因此，在循环结束后，务必检查 `scanner.Err()` 以确保没有发生错误。

   ```go
   scanner := bufio.NewScanner(file)
   for scanner.Scan() {
       // ... 处理每一行
   }
   if err := scanner.Err(); err != nil { // 容易忘记检查错误
       fmt.Println("Error reading file:", err)
   }
   ```

2. **假设 `scanner.Bytes()` 返回的数据一直有效:** `scanner.Bytes()` 返回的字节切片可能指向内部缓冲区，后续的 `Scan()` 调用可能会覆盖这些数据。 如果需要长期保存 token 的内容，应该使用 `scanner.Text()` 获取字符串副本，或者复制 `scanner.Bytes()` 返回的切片。

   ```go
   scanner := bufio.NewScanner(reader)
   for scanner.Scan() {
       tokenBytes := scanner.Bytes()
       // 错误的做法：在后续的循环迭代中，tokenBytes 的内容可能已经改变
       go processToken(tokenBytes)

       // 正确的做法：复制字节切片或使用 scanner.Text()
       tokenCopy := append([]byte{}, scanner.Bytes()...)
       go processToken(tokenCopy)

       tokenString := scanner.Text()
       go processTokenString(tokenString)
   }
   ```

3. **处理非常大的 Token:** 默认情况下，`Scanner` 有一个最大 token 大小的限制 (`MaxScanTokenSize`)。如果输入中存在超过这个大小的 token，`Scan()` 方法会返回 `false` 并且 `Err()` 方法会返回 `ErrTooLong`。  如果需要处理可能非常大的 token，可以使用 `Buffer()` 方法自定义缓冲区大小。

   ```go
   scanner := bufio.NewScanner(file)
   buf := make([]byte, 0, 64*1024) // 初始缓冲区大小
   scanner.Buffer(buf, 1024*1024)  // 设置最大缓冲区大小为 1MB
   for scanner.Scan() {
       // ...
   }
   if err := scanner.Err(); err != nil {
       if errors.Is(err, bufio.ErrTooLong) {
           fmt.Println("遇到过长的 token")
       } else {
           fmt.Println("读取文件时发生错误:", err)
       }
   }
   ```

理解这些功能和潜在的陷阱可以帮助你更有效地使用 `bufio.Scanner` 来处理文本数据。

### 提示词
```
这是路径为go/src/bufio/scan.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package bufio

import (
	"bytes"
	"errors"
	"io"
	"unicode/utf8"
)

// Scanner provides a convenient interface for reading data such as
// a file of newline-delimited lines of text. Successive calls to
// the [Scanner.Scan] method will step through the 'tokens' of a file, skipping
// the bytes between the tokens. The specification of a token is
// defined by a split function of type [SplitFunc]; the default split
// function breaks the input into lines with line termination stripped. [Scanner.Split]
// functions are defined in this package for scanning a file into
// lines, bytes, UTF-8-encoded runes, and space-delimited words. The
// client may instead provide a custom split function.
//
// Scanning stops unrecoverably at EOF, the first I/O error, or a token too
// large to fit in the [Scanner.Buffer]. When a scan stops, the reader may have
// advanced arbitrarily far past the last token. Programs that need more
// control over error handling or large tokens, or must run sequential scans
// on a reader, should use [bufio.Reader] instead.
type Scanner struct {
	r            io.Reader // The reader provided by the client.
	split        SplitFunc // The function to split the tokens.
	maxTokenSize int       // Maximum size of a token; modified by tests.
	token        []byte    // Last token returned by split.
	buf          []byte    // Buffer used as argument to split.
	start        int       // First non-processed byte in buf.
	end          int       // End of data in buf.
	err          error     // Sticky error.
	empties      int       // Count of successive empty tokens.
	scanCalled   bool      // Scan has been called; buffer is in use.
	done         bool      // Scan has finished.
}

// SplitFunc is the signature of the split function used to tokenize the
// input. The arguments are an initial substring of the remaining unprocessed
// data and a flag, atEOF, that reports whether the [Reader] has no more data
// to give. The return values are the number of bytes to advance the input
// and the next token to return to the user, if any, plus an error, if any.
//
// Scanning stops if the function returns an error, in which case some of
// the input may be discarded. If that error is [ErrFinalToken], scanning
// stops with no error. A non-nil token delivered with [ErrFinalToken]
// will be the last token, and a nil token with [ErrFinalToken]
// immediately stops the scanning.
//
// Otherwise, the [Scanner] advances the input. If the token is not nil,
// the [Scanner] returns it to the user. If the token is nil, the
// Scanner reads more data and continues scanning; if there is no more
// data--if atEOF was true--the [Scanner] returns. If the data does not
// yet hold a complete token, for instance if it has no newline while
// scanning lines, a [SplitFunc] can return (0, nil, nil) to signal the
// [Scanner] to read more data into the slice and try again with a
// longer slice starting at the same point in the input.
//
// The function is never called with an empty data slice unless atEOF
// is true. If atEOF is true, however, data may be non-empty and,
// as always, holds unprocessed text.
type SplitFunc func(data []byte, atEOF bool) (advance int, token []byte, err error)

// Errors returned by Scanner.
var (
	ErrTooLong         = errors.New("bufio.Scanner: token too long")
	ErrNegativeAdvance = errors.New("bufio.Scanner: SplitFunc returns negative advance count")
	ErrAdvanceTooFar   = errors.New("bufio.Scanner: SplitFunc returns advance count beyond input")
	ErrBadReadCount    = errors.New("bufio.Scanner: Read returned impossible count")
)

const (
	// MaxScanTokenSize is the maximum size used to buffer a token
	// unless the user provides an explicit buffer with [Scanner.Buffer].
	// The actual maximum token size may be smaller as the buffer
	// may need to include, for instance, a newline.
	MaxScanTokenSize = 64 * 1024

	startBufSize = 4096 // Size of initial allocation for buffer.
)

// NewScanner returns a new [Scanner] to read from r.
// The split function defaults to [ScanLines].
func NewScanner(r io.Reader) *Scanner {
	return &Scanner{
		r:            r,
		split:        ScanLines,
		maxTokenSize: MaxScanTokenSize,
	}
}

// Err returns the first non-EOF error that was encountered by the [Scanner].
func (s *Scanner) Err() error {
	if s.err == io.EOF {
		return nil
	}
	return s.err
}

// Bytes returns the most recent token generated by a call to [Scanner.Scan].
// The underlying array may point to data that will be overwritten
// by a subsequent call to Scan. It does no allocation.
func (s *Scanner) Bytes() []byte {
	return s.token
}

// Text returns the most recent token generated by a call to [Scanner.Scan]
// as a newly allocated string holding its bytes.
func (s *Scanner) Text() string {
	return string(s.token)
}

// ErrFinalToken is a special sentinel error value. It is intended to be
// returned by a Split function to indicate that the scanning should stop
// with no error. If the token being delivered with this error is not nil,
// the token is the last token.
//
// The value is useful to stop processing early or when it is necessary to
// deliver a final empty token (which is different from a nil token).
// One could achieve the same behavior with a custom error value but
// providing one here is tidier.
// See the emptyFinalToken example for a use of this value.
var ErrFinalToken = errors.New("final token")

// Scan advances the [Scanner] to the next token, which will then be
// available through the [Scanner.Bytes] or [Scanner.Text] method. It returns false when
// there are no more tokens, either by reaching the end of the input or an error.
// After Scan returns false, the [Scanner.Err] method will return any error that
// occurred during scanning, except that if it was [io.EOF], [Scanner.Err]
// will return nil.
// Scan panics if the split function returns too many empty
// tokens without advancing the input. This is a common error mode for
// scanners.
func (s *Scanner) Scan() bool {
	if s.done {
		return false
	}
	s.scanCalled = true
	// Loop until we have a token.
	for {
		// See if we can get a token with what we already have.
		// If we've run out of data but have an error, give the split function
		// a chance to recover any remaining, possibly empty token.
		if s.end > s.start || s.err != nil {
			advance, token, err := s.split(s.buf[s.start:s.end], s.err != nil)
			if err != nil {
				if err == ErrFinalToken {
					s.token = token
					s.done = true
					// When token is not nil, it means the scanning stops
					// with a trailing token, and thus the return value
					// should be true to indicate the existence of the token.
					return token != nil
				}
				s.setErr(err)
				return false
			}
			if !s.advance(advance) {
				return false
			}
			s.token = token
			if token != nil {
				if s.err == nil || advance > 0 {
					s.empties = 0
				} else {
					// Returning tokens not advancing input at EOF.
					s.empties++
					if s.empties > maxConsecutiveEmptyReads {
						panic("bufio.Scan: too many empty tokens without progressing")
					}
				}
				return true
			}
		}
		// We cannot generate a token with what we are holding.
		// If we've already hit EOF or an I/O error, we are done.
		if s.err != nil {
			// Shut it down.
			s.start = 0
			s.end = 0
			return false
		}
		// Must read more data.
		// First, shift data to beginning of buffer if there's lots of empty space
		// or space is needed.
		if s.start > 0 && (s.end == len(s.buf) || s.start > len(s.buf)/2) {
			copy(s.buf, s.buf[s.start:s.end])
			s.end -= s.start
			s.start = 0
		}
		// Is the buffer full? If so, resize.
		if s.end == len(s.buf) {
			// Guarantee no overflow in the multiplication below.
			const maxInt = int(^uint(0) >> 1)
			if len(s.buf) >= s.maxTokenSize || len(s.buf) > maxInt/2 {
				s.setErr(ErrTooLong)
				return false
			}
			newSize := len(s.buf) * 2
			if newSize == 0 {
				newSize = startBufSize
			}
			newSize = min(newSize, s.maxTokenSize)
			newBuf := make([]byte, newSize)
			copy(newBuf, s.buf[s.start:s.end])
			s.buf = newBuf
			s.end -= s.start
			s.start = 0
		}
		// Finally we can read some input. Make sure we don't get stuck with
		// a misbehaving Reader. Officially we don't need to do this, but let's
		// be extra careful: Scanner is for safe, simple jobs.
		for loop := 0; ; {
			n, err := s.r.Read(s.buf[s.end:len(s.buf)])
			if n < 0 || len(s.buf)-s.end < n {
				s.setErr(ErrBadReadCount)
				break
			}
			s.end += n
			if err != nil {
				s.setErr(err)
				break
			}
			if n > 0 {
				s.empties = 0
				break
			}
			loop++
			if loop > maxConsecutiveEmptyReads {
				s.setErr(io.ErrNoProgress)
				break
			}
		}
	}
}

// advance consumes n bytes of the buffer. It reports whether the advance was legal.
func (s *Scanner) advance(n int) bool {
	if n < 0 {
		s.setErr(ErrNegativeAdvance)
		return false
	}
	if n > s.end-s.start {
		s.setErr(ErrAdvanceTooFar)
		return false
	}
	s.start += n
	return true
}

// setErr records the first error encountered.
func (s *Scanner) setErr(err error) {
	if s.err == nil || s.err == io.EOF {
		s.err = err
	}
}

// Buffer sets the initial buffer to use when scanning
// and the maximum size of buffer that may be allocated during scanning.
// The maximum token size must be less than the larger of max and cap(buf).
// If max <= cap(buf), [Scanner.Scan] will use this buffer only and do no allocation.
//
// By default, [Scanner.Scan] uses an internal buffer and sets the
// maximum token size to [MaxScanTokenSize].
//
// Buffer panics if it is called after scanning has started.
func (s *Scanner) Buffer(buf []byte, max int) {
	if s.scanCalled {
		panic("Buffer called after Scan")
	}
	s.buf = buf[0:cap(buf)]
	s.maxTokenSize = max
}

// Split sets the split function for the [Scanner].
// The default split function is [ScanLines].
//
// Split panics if it is called after scanning has started.
func (s *Scanner) Split(split SplitFunc) {
	if s.scanCalled {
		panic("Split called after Scan")
	}
	s.split = split
}

// Split functions

// ScanBytes is a split function for a [Scanner] that returns each byte as a token.
func ScanBytes(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	return 1, data[0:1], nil
}

var errorRune = []byte(string(utf8.RuneError))

// ScanRunes is a split function for a [Scanner] that returns each
// UTF-8-encoded rune as a token. The sequence of runes returned is
// equivalent to that from a range loop over the input as a string, which
// means that erroneous UTF-8 encodings translate to U+FFFD = "\xef\xbf\xbd".
// Because of the Scan interface, this makes it impossible for the client to
// distinguish correctly encoded replacement runes from encoding errors.
func ScanRunes(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	// Fast path 1: ASCII.
	if data[0] < utf8.RuneSelf {
		return 1, data[0:1], nil
	}

	// Fast path 2: Correct UTF-8 decode without error.
	_, width := utf8.DecodeRune(data)
	if width > 1 {
		// It's a valid encoding. Width cannot be one for a correctly encoded
		// non-ASCII rune.
		return width, data[0:width], nil
	}

	// We know it's an error: we have width==1 and implicitly r==utf8.RuneError.
	// Is the error because there wasn't a full rune to be decoded?
	// FullRune distinguishes correctly between erroneous and incomplete encodings.
	if !atEOF && !utf8.FullRune(data) {
		// Incomplete; get more bytes.
		return 0, nil, nil
	}

	// We have a real UTF-8 encoding error. Return a properly encoded error rune
	// but advance only one byte. This matches the behavior of a range loop over
	// an incorrectly encoded string.
	return 1, errorRune, nil
}

// dropCR drops a terminal \r from the data.
func dropCR(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\r' {
		return data[0 : len(data)-1]
	}
	return data
}

// ScanLines is a split function for a [Scanner] that returns each line of
// text, stripped of any trailing end-of-line marker. The returned line may
// be empty. The end-of-line marker is one optional carriage return followed
// by one mandatory newline. In regular expression notation, it is `\r?\n`.
// The last non-empty line of input will be returned even if it has no
// newline.
func ScanLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		// We have a full newline-terminated line.
		return i + 1, dropCR(data[0:i]), nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), dropCR(data), nil
	}
	// Request more data.
	return 0, nil, nil
}

// isSpace reports whether the character is a Unicode white space character.
// We avoid dependency on the unicode package, but check validity of the implementation
// in the tests.
func isSpace(r rune) bool {
	if r <= '\u00FF' {
		// Obvious ASCII ones: \t through \r plus space. Plus two Latin-1 oddballs.
		switch r {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			return true
		case '\u0085', '\u00A0':
			return true
		}
		return false
	}
	// High-valued ones.
	if '\u2000' <= r && r <= '\u200a' {
		return true
	}
	switch r {
	case '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000':
		return true
	}
	return false
}

// ScanWords is a split function for a [Scanner] that returns each
// space-separated word of text, with surrounding spaces deleted. It will
// never return an empty string. The definition of space is set by
// unicode.IsSpace.
func ScanWords(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip leading spaces.
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !isSpace(r) {
			break
		}
	}
	// Scan until space, marking end of word.
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])
		if isSpace(r) {
			return i + width, data[start:i], nil
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
	if atEOF && len(data) > start {
		return len(data), data[start:], nil
	}
	// Request more data.
	return start, nil, nil
}
```