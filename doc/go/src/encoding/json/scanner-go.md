Response:
Let's break down the thought process for answering this request.

**1. Understanding the Core Request:**

The central task is to analyze the provided Go code (`scanner.go`) and explain its functionality. The request also specifically asks for:

*   Listing the functions.
*   Inferring the Go language feature it implements.
*   Providing code examples.
*   Explaining command-line argument handling (if any).
*   Highlighting common user errors.
*   Using Chinese.

**2. Initial Code Scan and Identification of Key Components:**

The first step is to skim the code and identify the major structural elements:

*   **Package Declaration:** `package json` -  This immediately tells us it's part of the standard `encoding/json` package, strongly suggesting it's related to JSON processing.
*   **Imports:** `strconv`, `sync` - These indicate dependencies on string conversion and synchronization primitives, hinting at parsing and potentially thread safety.
*   **`Valid` Function:**  A function named `Valid` that takes `[]byte` and returns `bool` strongly suggests validation.
*   **`checkValid` Function:**  This function takes `[]byte` and a `scanner` pointer, further reinforcing the validation idea and introducing the central `scanner` type.
*   **`SyntaxError` Type:**  This clearly defines a specific error type for JSON syntax issues.
*   **`scanner` Type:**  This struct is the heart of the code, containing state information (`step`, `parseState`, `err`, `bytes`, `endTop`). The comment about a "JSON scanning state machine" is a crucial clue.
*   **Constants:** `scanContinue`, `scanBeginLiteral`, etc., and `parseObjectKey`, `parseObjectValue`, etc., point towards a state machine implementation.
*   **`scannerPool`:** The `sync.Pool` suggests that `scanner` instances are being reused to optimize performance.
*   **State Functions:**  Functions like `stateBeginValue`, `stateInString`, `stateNeg`, etc., strongly confirm the state machine nature.

**3. Inferring the Go Feature:**

Based on the above observations, the most likely Go language feature being implemented is **JSON parsing and validation**. The structure, the naming conventions, and the state machine approach all align with how a parser would be built. The `encoding/json` package context confirms this.

**4. Explaining the Functionality:**

Now, we need to articulate *how* the code works.

*   **`Valid(data []byte)`:** This is the entry point for simple validation. It creates a `scanner`, feeds the data, and returns `true` if no errors occur.
*   **`checkValid(data []byte, scan *scanner)`:** This is the core validation logic. It initializes the `scanner` and iterates through the input byte by byte, calling the `scan.step` function to transition between states. The return value of `scan.step` indicates the parsing event.
*   **`SyntaxError`:**  A standard error type for reporting JSON syntax issues, providing a message and the offset of the error.
*   **`scanner`:** The core state machine. It maintains the current parsing state and uses a function pointer (`step`) to represent the next state transition. The `parseState` stack keeps track of the nesting level of objects and arrays.
*   **State Transitions:** The various `state...` functions define the transitions between parsing states based on the input byte. They handle different JSON constructs like objects, arrays, strings, numbers, and literals.

**5. Creating Code Examples:**

To illustrate the functionality, we need examples of valid and invalid JSON:

*   **Valid Example:**  A simple JSON object is a good starting point: `{"key": "value"}`. The output should be `true`.
*   **Invalid Example:** Introduce a syntax error, like a missing quote: `{"key": value}`. The output should be `false`. It's also helpful to show how to access the `SyntaxError` for more details.

**6. Addressing Command-Line Arguments:**

A careful review of the code shows *no* direct handling of command-line arguments. This is an important observation.

**7. Identifying Common User Errors:**

Thinking about how people interact with JSON and parsers, common errors include:

*   **Missing quotes around string keys or values.**
*   **Incorrectly formatted numbers.**
*   **Trailing commas in arrays or objects.**
*   **Unmatched braces or brackets.**
*   **Incorrect capitalization of `true`, `false`, or `null`.**

Provide concrete examples for each of these.

**8. Structuring the Answer in Chinese:**

Translate the explanations, code examples, and error descriptions into clear and concise Chinese. Pay attention to technical terminology.

**9. Review and Refinement:**

After drafting the answer, review it for accuracy, clarity, and completeness. Ensure that all parts of the original request have been addressed. Double-check the code examples and their expected outputs.

**Self-Correction/Refinement Example During Thought Process:**

Initially, I might focus heavily on the individual state transitions. However, realizing the high-level goal is to understand the *functionality*, I would shift the focus to explaining the overall purpose of the `scanner` and how the states contribute to validating the JSON structure. I would also prioritize providing practical examples over a detailed walkthrough of each state transition function, as the former is more directly useful to someone understanding the code's purpose. Similarly, noticing the lack of command-line argument handling is crucial – don't invent functionality that isn't there. Finally, ensuring the answer is in fluent and accurate Chinese is paramount given the language constraint.
这段代码是 Go 语言 `encoding/json` 标准库中 `scanner.go` 文件的一部分，它实现了一个 **JSON 值的扫描器（scanner）**。 它的主要功能是**验证给定的字节切片是否是合法的 JSON 编码**。

更具体地说，`scanner.go` 实现了一个 **状态机**，用于逐字节地解析 JSON 数据，并判断其语法是否正确。

**功能列表:**

1. **`Valid(data []byte) bool`:**  接收一个字节切片 `data`，判断它是否是有效的 JSON 编码，并返回布尔值。这是对外提供的最简单的验证 JSON 数据的方法。
2. **`checkValid(data []byte, scan *scanner) error`:**  核心的验证函数。它接收一个字节切片 `data` 和一个 `scanner` 类型的指针 `scan`。它会重置 `scanner` 的状态，然后逐字节地输入 `data` 给 `scanner` 的状态机进行处理。如果发现任何语法错误，它会返回一个 `SyntaxError` 类型的错误，否则返回 `nil`。使用传入的 `scanner` 可以避免重复分配内存。
3. **`SyntaxError` 类型:**  定义了一个结构体，用于表示 JSON 语法错误，包含错误消息 `msg` 和错误发生的偏移量 `Offset`。`Unmarshal` 函数在解析 JSON 失败时会返回这个类型的错误。
4. **`scanner` 类型:**  定义了 JSON 扫描器的状态机。它包含：
    *   `step func(*scanner, byte) int`:  一个函数，代表当前状态需要执行的状态转换。
    *   `endTop bool`:  一个布尔值，表示是否已经到达顶层 JSON 值的末尾。
    *   `parseState []int`:  一个整数切片，作为栈使用，用于跟踪当前解析的嵌套结构（例如，在数组或对象内部）。
    *   `err error`:  存储发生的任何错误。
    *   `bytes int64`:  记录已消费的字节总数。
5. **`newScanner() *scanner` 和 `freeScanner(scan *scanner)`:** 使用 `sync.Pool` 实现的 `scanner` 对象池，用于提高性能，避免频繁地创建和销毁 `scanner` 对象。
6. **常量定义 (`scanContinue`, `scanBeginLiteral`, ... 和 `parseObjectKey`, `parseObjectValue`, ...)`:** 定义了状态机中各种状态转换的返回值和解析状态的值。这些常量用于标识扫描过程中的重要事件。
7. **状态转换函数 (`stateBeginValue`, `stateInString`, `stateNeg`, 等等)`:**  一系列以 `state` 开头的函数，实现了状态机的各个状态。每个函数接收当前的 `scanner` 和一个字节，根据这个字节来决定下一个状态，并返回一个表示状态转换的常量。
8. **辅助函数 (`isSpace`, `pushParseState`, `popParseState`, `error`, `quoteChar`)`:**  提供了一些辅助功能，例如判断是否是空白字符，压入和弹出解析状态，记录错误信息和格式化字符。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言标准库中 **`encoding/json` 包中用于验证 JSON 数据的功能** 的实现。它并不直接参与将 JSON 数据反序列化为 Go 语言的对象，而是专注于**语法检查**。

**Go 代码举例说明:**

```go
package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	validJSON := []byte(`{"name": "Alice", "age": 30}`)
	invalidJSON := []byte(`{"name": "Alice", "age": 30`) // 缺少右大括号

	isValid := json.Valid(validJSON)
	fmt.Printf("Valid JSON: %v\n", isValid) // 输出: Valid JSON: true

	isValid = json.Valid(invalidJSON)
	fmt.Printf("Invalid JSON: %v\n", isValid) // 输出: Invalid JSON: false

	// 使用 checkValid 可以获取更详细的错误信息
	var scan json.scanner
	err := json.checkValid(invalidJSON, &scan)
	if err != nil {
		fmt.Printf("Validation error: %v\n", err) // 输出: Validation error: invalid character '\x00' looking for beginning of value
	}
}
```

**假设的输入与输出:**

*   **输入:** `[]byte(`{"key": "value"}`)`
*   **输出:** `json.Valid` 函数返回 `true`

*   **输入:** `[]byte(`{"key": value}`)`
*   **输出:** `json.Valid` 函数返回 `false`，`json.checkValid` 函数返回一个 `*json.SyntaxError`，其 `msg` 可能包含 "invalid character 'v' looking for beginning of value"， `Offset` 指向 'v' 的位置。

**命令行参数的具体处理:**

这段代码本身 **没有直接处理命令行参数**。它的功能是作为 `encoding/json` 包的一部分，供其他 Go 代码使用。如果需要从命令行读取 JSON 数据并进行验证，你需要编写额外的 Go 代码来处理命令行参数，并将读取到的数据传递给 `json.Valid` 或 `json.checkValid` 函数。

例如，你可以使用 `flag` 包来解析命令行参数，然后读取文件或标准输入中的 JSON 数据：

```go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	filePath := flag.String("file", "", "Path to the JSON file")
	flag.Parse()

	var data []byte
	var err error

	if *filePath != "" {
		data, err = ioutil.ReadFile(*filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
	} else {
		data, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
	}

	isValid := json.Valid(data)
	fmt.Printf("JSON is valid: %v\n", isValid)
}
```

在这个例子中，使用了 `-file` 命令行参数来指定 JSON 文件的路径。

**使用者易犯错的点:**

一个常见的易错点是**误以为 `json.Valid` 或 `checkValid` 会对 JSON 数据进行任何修改或格式化**。 这两个函数仅仅是进行语法验证，并不会改变输入的 JSON 数据。

另一个易错点是**忽略 `checkValid` 返回的 `SyntaxError` 提供的详细信息**。 当 JSON 数据无效时，`SyntaxError` 包含了错误发生的位置和原因，这对于调试问题非常重要。仅仅判断 `json.Valid` 的返回值是不够的，应该在必要时使用 `checkValid` 并检查返回的错误信息。

例如，如果用户有一个格式错误的 JSON 字符串，直接使用 `json.Unmarshal` 可能会得到一个不太清晰的错误信息。但是如果先使用 `json.checkValid`，就可以更早地发现语法错误，并根据 `SyntaxError` 提供的信息定位问题所在。

总而言之，`go/src/encoding/json/scanner.go` 中的代码实现了 JSON 语法验证的核心逻辑，通过状态机的方式高效地判断给定的字节切片是否符合 JSON 规范。 它为 `encoding/json` 包的其他功能（如 `Unmarshal`）提供了基础的语法检查能力。

Prompt: 
```
这是路径为go/src/encoding/json/scanner.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

// JSON value parser state machine.
// Just about at the limit of what is reasonable to write by hand.
// Some parts are a bit tedious, but overall it nicely factors out the
// otherwise common code from the multiple scanning functions
// in this package (Compact, Indent, checkValid, etc).
//
// This file starts with two simple examples using the scanner
// before diving into the scanner itself.

import (
	"strconv"
	"sync"
)

// Valid reports whether data is a valid JSON encoding.
func Valid(data []byte) bool {
	scan := newScanner()
	defer freeScanner(scan)
	return checkValid(data, scan) == nil
}

// checkValid verifies that data is valid JSON-encoded data.
// scan is passed in for use by checkValid to avoid an allocation.
// checkValid returns nil or a SyntaxError.
func checkValid(data []byte, scan *scanner) error {
	scan.reset()
	for _, c := range data {
		scan.bytes++
		if scan.step(scan, c) == scanError {
			return scan.err
		}
	}
	if scan.eof() == scanError {
		return scan.err
	}
	return nil
}

// A SyntaxError is a description of a JSON syntax error.
// [Unmarshal] will return a SyntaxError if the JSON can't be parsed.
type SyntaxError struct {
	msg    string // description of error
	Offset int64  // error occurred after reading Offset bytes
}

func (e *SyntaxError) Error() string { return e.msg }

// A scanner is a JSON scanning state machine.
// Callers call scan.reset and then pass bytes in one at a time
// by calling scan.step(&scan, c) for each byte.
// The return value, referred to as an opcode, tells the
// caller about significant parsing events like beginning
// and ending literals, objects, and arrays, so that the
// caller can follow along if it wishes.
// The return value scanEnd indicates that a single top-level
// JSON value has been completed, *before* the byte that
// just got passed in.  (The indication must be delayed in order
// to recognize the end of numbers: is 123 a whole value or
// the beginning of 12345e+6?).
type scanner struct {
	// The step is a func to be called to execute the next transition.
	// Also tried using an integer constant and a single func
	// with a switch, but using the func directly was 10% faster
	// on a 64-bit Mac Mini, and it's nicer to read.
	step func(*scanner, byte) int

	// Reached end of top-level value.
	endTop bool

	// Stack of what we're in the middle of - array values, object keys, object values.
	parseState []int

	// Error that happened, if any.
	err error

	// total bytes consumed, updated by decoder.Decode (and deliberately
	// not set to zero by scan.reset)
	bytes int64
}

var scannerPool = sync.Pool{
	New: func() any {
		return &scanner{}
	},
}

func newScanner() *scanner {
	scan := scannerPool.Get().(*scanner)
	// scan.reset by design doesn't set bytes to zero
	scan.bytes = 0
	scan.reset()
	return scan
}

func freeScanner(scan *scanner) {
	// Avoid hanging on to too much memory in extreme cases.
	if len(scan.parseState) > 1024 {
		scan.parseState = nil
	}
	scannerPool.Put(scan)
}

// These values are returned by the state transition functions
// assigned to scanner.state and the method scanner.eof.
// They give details about the current state of the scan that
// callers might be interested to know about.
// It is okay to ignore the return value of any particular
// call to scanner.state: if one call returns scanError,
// every subsequent call will return scanError too.
const (
	// Continue.
	scanContinue     = iota // uninteresting byte
	scanBeginLiteral        // end implied by next result != scanContinue
	scanBeginObject         // begin object
	scanObjectKey           // just finished object key (string)
	scanObjectValue         // just finished non-last object value
	scanEndObject           // end object (implies scanObjectValue if possible)
	scanBeginArray          // begin array
	scanArrayValue          // just finished array value
	scanEndArray            // end array (implies scanArrayValue if possible)
	scanSkipSpace           // space byte; can skip; known to be last "continue" result

	// Stop.
	scanEnd   // top-level value ended *before* this byte; known to be first "stop" result
	scanError // hit an error, scanner.err.
)

// These values are stored in the parseState stack.
// They give the current state of a composite value
// being scanned. If the parser is inside a nested value
// the parseState describes the nested state, outermost at entry 0.
const (
	parseObjectKey   = iota // parsing object key (before colon)
	parseObjectValue        // parsing object value (after colon)
	parseArrayValue         // parsing array value
)

// This limits the max nesting depth to prevent stack overflow.
// This is permitted by https://tools.ietf.org/html/rfc7159#section-9
const maxNestingDepth = 10000

// reset prepares the scanner for use.
// It must be called before calling s.step.
func (s *scanner) reset() {
	s.step = stateBeginValue
	s.parseState = s.parseState[0:0]
	s.err = nil
	s.endTop = false
}

// eof tells the scanner that the end of input has been reached.
// It returns a scan status just as s.step does.
func (s *scanner) eof() int {
	if s.err != nil {
		return scanError
	}
	if s.endTop {
		return scanEnd
	}
	s.step(s, ' ')
	if s.endTop {
		return scanEnd
	}
	if s.err == nil {
		s.err = &SyntaxError{"unexpected end of JSON input", s.bytes}
	}
	return scanError
}

// pushParseState pushes a new parse state p onto the parse stack.
// an error state is returned if maxNestingDepth was exceeded, otherwise successState is returned.
func (s *scanner) pushParseState(c byte, newParseState int, successState int) int {
	s.parseState = append(s.parseState, newParseState)
	if len(s.parseState) <= maxNestingDepth {
		return successState
	}
	return s.error(c, "exceeded max depth")
}

// popParseState pops a parse state (already obtained) off the stack
// and updates s.step accordingly.
func (s *scanner) popParseState() {
	n := len(s.parseState) - 1
	s.parseState = s.parseState[0:n]
	if n == 0 {
		s.step = stateEndTop
		s.endTop = true
	} else {
		s.step = stateEndValue
	}
}

func isSpace(c byte) bool {
	return c <= ' ' && (c == ' ' || c == '\t' || c == '\r' || c == '\n')
}

// stateBeginValueOrEmpty is the state after reading `[`.
func stateBeginValueOrEmpty(s *scanner, c byte) int {
	if isSpace(c) {
		return scanSkipSpace
	}
	if c == ']' {
		return stateEndValue(s, c)
	}
	return stateBeginValue(s, c)
}

// stateBeginValue is the state at the beginning of the input.
func stateBeginValue(s *scanner, c byte) int {
	if isSpace(c) {
		return scanSkipSpace
	}
	switch c {
	case '{':
		s.step = stateBeginStringOrEmpty
		return s.pushParseState(c, parseObjectKey, scanBeginObject)
	case '[':
		s.step = stateBeginValueOrEmpty
		return s.pushParseState(c, parseArrayValue, scanBeginArray)
	case '"':
		s.step = stateInString
		return scanBeginLiteral
	case '-':
		s.step = stateNeg
		return scanBeginLiteral
	case '0': // beginning of 0.123
		s.step = state0
		return scanBeginLiteral
	case 't': // beginning of true
		s.step = stateT
		return scanBeginLiteral
	case 'f': // beginning of false
		s.step = stateF
		return scanBeginLiteral
	case 'n': // beginning of null
		s.step = stateN
		return scanBeginLiteral
	}
	if '1' <= c && c <= '9' { // beginning of 1234.5
		s.step = state1
		return scanBeginLiteral
	}
	return s.error(c, "looking for beginning of value")
}

// stateBeginStringOrEmpty is the state after reading `{`.
func stateBeginStringOrEmpty(s *scanner, c byte) int {
	if isSpace(c) {
		return scanSkipSpace
	}
	if c == '}' {
		n := len(s.parseState)
		s.parseState[n-1] = parseObjectValue
		return stateEndValue(s, c)
	}
	return stateBeginString(s, c)
}

// stateBeginString is the state after reading `{"key": value,`.
func stateBeginString(s *scanner, c byte) int {
	if isSpace(c) {
		return scanSkipSpace
	}
	if c == '"' {
		s.step = stateInString
		return scanBeginLiteral
	}
	return s.error(c, "looking for beginning of object key string")
}

// stateEndValue is the state after completing a value,
// such as after reading `{}` or `true` or `["x"`.
func stateEndValue(s *scanner, c byte) int {
	n := len(s.parseState)
	if n == 0 {
		// Completed top-level before the current byte.
		s.step = stateEndTop
		s.endTop = true
		return stateEndTop(s, c)
	}
	if isSpace(c) {
		s.step = stateEndValue
		return scanSkipSpace
	}
	ps := s.parseState[n-1]
	switch ps {
	case parseObjectKey:
		if c == ':' {
			s.parseState[n-1] = parseObjectValue
			s.step = stateBeginValue
			return scanObjectKey
		}
		return s.error(c, "after object key")
	case parseObjectValue:
		if c == ',' {
			s.parseState[n-1] = parseObjectKey
			s.step = stateBeginString
			return scanObjectValue
		}
		if c == '}' {
			s.popParseState()
			return scanEndObject
		}
		return s.error(c, "after object key:value pair")
	case parseArrayValue:
		if c == ',' {
			s.step = stateBeginValue
			return scanArrayValue
		}
		if c == ']' {
			s.popParseState()
			return scanEndArray
		}
		return s.error(c, "after array element")
	}
	return s.error(c, "")
}

// stateEndTop is the state after finishing the top-level value,
// such as after reading `{}` or `[1,2,3]`.
// Only space characters should be seen now.
func stateEndTop(s *scanner, c byte) int {
	if !isSpace(c) {
		// Complain about non-space byte on next call.
		s.error(c, "after top-level value")
	}
	return scanEnd
}

// stateInString is the state after reading `"`.
func stateInString(s *scanner, c byte) int {
	if c == '"' {
		s.step = stateEndValue
		return scanContinue
	}
	if c == '\\' {
		s.step = stateInStringEsc
		return scanContinue
	}
	if c < 0x20 {
		return s.error(c, "in string literal")
	}
	return scanContinue
}

// stateInStringEsc is the state after reading `"\` during a quoted string.
func stateInStringEsc(s *scanner, c byte) int {
	switch c {
	case 'b', 'f', 'n', 'r', 't', '\\', '/', '"':
		s.step = stateInString
		return scanContinue
	case 'u':
		s.step = stateInStringEscU
		return scanContinue
	}
	return s.error(c, "in string escape code")
}

// stateInStringEscU is the state after reading `"\u` during a quoted string.
func stateInStringEscU(s *scanner, c byte) int {
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
		s.step = stateInStringEscU1
		return scanContinue
	}
	// numbers
	return s.error(c, "in \\u hexadecimal character escape")
}

// stateInStringEscU1 is the state after reading `"\u1` during a quoted string.
func stateInStringEscU1(s *scanner, c byte) int {
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
		s.step = stateInStringEscU12
		return scanContinue
	}
	// numbers
	return s.error(c, "in \\u hexadecimal character escape")
}

// stateInStringEscU12 is the state after reading `"\u12` during a quoted string.
func stateInStringEscU12(s *scanner, c byte) int {
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
		s.step = stateInStringEscU123
		return scanContinue
	}
	// numbers
	return s.error(c, "in \\u hexadecimal character escape")
}

// stateInStringEscU123 is the state after reading `"\u123` during a quoted string.
func stateInStringEscU123(s *scanner, c byte) int {
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
		s.step = stateInString
		return scanContinue
	}
	// numbers
	return s.error(c, "in \\u hexadecimal character escape")
}

// stateNeg is the state after reading `-` during a number.
func stateNeg(s *scanner, c byte) int {
	if c == '0' {
		s.step = state0
		return scanContinue
	}
	if '1' <= c && c <= '9' {
		s.step = state1
		return scanContinue
	}
	return s.error(c, "in numeric literal")
}

// state1 is the state after reading a non-zero integer during a number,
// such as after reading `1` or `100` but not `0`.
func state1(s *scanner, c byte) int {
	if '0' <= c && c <= '9' {
		s.step = state1
		return scanContinue
	}
	return state0(s, c)
}

// state0 is the state after reading `0` during a number.
func state0(s *scanner, c byte) int {
	if c == '.' {
		s.step = stateDot
		return scanContinue
	}
	if c == 'e' || c == 'E' {
		s.step = stateE
		return scanContinue
	}
	return stateEndValue(s, c)
}

// stateDot is the state after reading the integer and decimal point in a number,
// such as after reading `1.`.
func stateDot(s *scanner, c byte) int {
	if '0' <= c && c <= '9' {
		s.step = stateDot0
		return scanContinue
	}
	return s.error(c, "after decimal point in numeric literal")
}

// stateDot0 is the state after reading the integer, decimal point, and subsequent
// digits of a number, such as after reading `3.14`.
func stateDot0(s *scanner, c byte) int {
	if '0' <= c && c <= '9' {
		return scanContinue
	}
	if c == 'e' || c == 'E' {
		s.step = stateE
		return scanContinue
	}
	return stateEndValue(s, c)
}

// stateE is the state after reading the mantissa and e in a number,
// such as after reading `314e` or `0.314e`.
func stateE(s *scanner, c byte) int {
	if c == '+' || c == '-' {
		s.step = stateESign
		return scanContinue
	}
	return stateESign(s, c)
}

// stateESign is the state after reading the mantissa, e, and sign in a number,
// such as after reading `314e-` or `0.314e+`.
func stateESign(s *scanner, c byte) int {
	if '0' <= c && c <= '9' {
		s.step = stateE0
		return scanContinue
	}
	return s.error(c, "in exponent of numeric literal")
}

// stateE0 is the state after reading the mantissa, e, optional sign,
// and at least one digit of the exponent in a number,
// such as after reading `314e-2` or `0.314e+1` or `3.14e0`.
func stateE0(s *scanner, c byte) int {
	if '0' <= c && c <= '9' {
		return scanContinue
	}
	return stateEndValue(s, c)
}

// stateT is the state after reading `t`.
func stateT(s *scanner, c byte) int {
	if c == 'r' {
		s.step = stateTr
		return scanContinue
	}
	return s.error(c, "in literal true (expecting 'r')")
}

// stateTr is the state after reading `tr`.
func stateTr(s *scanner, c byte) int {
	if c == 'u' {
		s.step = stateTru
		return scanContinue
	}
	return s.error(c, "in literal true (expecting 'u')")
}

// stateTru is the state after reading `tru`.
func stateTru(s *scanner, c byte) int {
	if c == 'e' {
		s.step = stateEndValue
		return scanContinue
	}
	return s.error(c, "in literal true (expecting 'e')")
}

// stateF is the state after reading `f`.
func stateF(s *scanner, c byte) int {
	if c == 'a' {
		s.step = stateFa
		return scanContinue
	}
	return s.error(c, "in literal false (expecting 'a')")
}

// stateFa is the state after reading `fa`.
func stateFa(s *scanner, c byte) int {
	if c == 'l' {
		s.step = stateFal
		return scanContinue
	}
	return s.error(c, "in literal false (expecting 'l')")
}

// stateFal is the state after reading `fal`.
func stateFal(s *scanner, c byte) int {
	if c == 's' {
		s.step = stateFals
		return scanContinue
	}
	return s.error(c, "in literal false (expecting 's')")
}

// stateFals is the state after reading `fals`.
func stateFals(s *scanner, c byte) int {
	if c == 'e' {
		s.step = stateEndValue
		return scanContinue
	}
	return s.error(c, "in literal false (expecting 'e')")
}

// stateN is the state after reading `n`.
func stateN(s *scanner, c byte) int {
	if c == 'u' {
		s.step = stateNu
		return scanContinue
	}
	return s.error(c, "in literal null (expecting 'u')")
}

// stateNu is the state after reading `nu`.
func stateNu(s *scanner, c byte) int {
	if c == 'l' {
		s.step = stateNul
		return scanContinue
	}
	return s.error(c, "in literal null (expecting 'l')")
}

// stateNul is the state after reading `nul`.
func stateNul(s *scanner, c byte) int {
	if c == 'l' {
		s.step = stateEndValue
		return scanContinue
	}
	return s.error(c, "in literal null (expecting 'l')")
}

// stateError is the state after reaching a syntax error,
// such as after reading `[1}` or `5.1.2`.
func stateError(s *scanner, c byte) int {
	return scanError
}

// error records an error and switches to the error state.
func (s *scanner) error(c byte, context string) int {
	s.step = stateError
	s.err = &SyntaxError{"invalid character " + quoteChar(c) + " " + context, s.bytes}
	return scanError
}

// quoteChar formats c as a quoted character literal.
func quoteChar(c byte) string {
	// special cases - different from quoted strings
	if c == '\'' {
		return `'\''`
	}
	if c == '"' {
		return `'"'`
	}

	// use quoted string with different quotation marks
	s := strconv.Quote(string(c))
	return "'" + s[1:len(s)-1] + "'"
}

"""



```