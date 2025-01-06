Response:
Let's break down the thought process for analyzing the provided Go code snippet for `terminal.go`.

**1. Initial Understanding and Goal:**

The core request is to understand the *functionality* of this Go code and demonstrate some key aspects with examples. The target audience is someone familiar with Go but perhaps not deeply familiar with terminal manipulation.

**2. High-Level Overview and Keyword Spotting:**

My first step is to skim the code, looking for major structures and keywords that hint at the purpose. I see:

* `package term`: Clearly about terminal interaction.
* `EscapeCodes`: Suggests dealing with terminal escape sequences for formatting.
* `Terminal struct`: The main data structure, holding the terminal state.
* Methods like `NewTerminal`, `ReadLine`, `Write`, `ReadPassword`, `SetPrompt`, `SetSize`, `SetBracketedPasteMode`. These are the primary actions the `Terminal` can perform.
* Fields within `Terminal`:  `AutoCompleteCallback`, `Escape`, `lock`, `c`, `prompt`, `line`, `pos`, `echo`, `pasteActive`, cursor positions, buffer (`outBuf`, `inBuf`), history. These represent the internal state.
* Constants like `keyCtrlC`, `keyEnter`, `keyEscape`, and functions like `bytesToKey`. These deal with input interpretation.

From this initial skim, I can already infer that this code implements a virtual terminal, handling input, output, and providing features like auto-completion, history, and password input.

**3. Deeper Dive into Key Structures and Methods:**

Now, I focus on understanding how the pieces fit together.

* **`EscapeCodes`**:  This is straightforward. It defines escape sequences for basic text styling (colors, reset).
* **`Terminal` struct**: I examine each field to understand its role:
    * `AutoCompleteCallback`:  A function hook for providing auto-completion.
    * `Escape`: Pointer to the styling codes.
    * `lock`:  Essential for thread safety, suggesting concurrent access.
    * `c`:  The underlying `io.ReadWriter`, representing the actual terminal.
    * `prompt`: The text displayed at the beginning of a line.
    * `line`, `pos`: The currently entered line and the cursor position.
    * `echo`: Whether to display typed characters.
    * `pasteActive`:  Handles bracketed paste mode.
    * Cursor and dimensions: Track the cursor's visual location and terminal size.
    * Buffers:  `outBuf` for data to send, `inBuf` and `remainder` for handling input.
    * `history`:  Stores previous commands.
* **`NewTerminal`**: The constructor, initializing basic terminal settings.
* **`bytesToKey`**:  Crucial for mapping byte sequences from the terminal to meaningful key presses (including special keys and escape sequences). The `pasteActive` parameter is interesting, hinting at different handling during pastes.
* **Input Handling (`handleKey`)**:  This is the core logic. It uses a `switch` statement to process different key presses. I pay attention to how each key affects the `line`, `pos`, and triggers output to the terminal via `queue`. The interaction with `AutoCompleteCallback` is also important.
* **Output Handling (`queue`, `moveCursorToPos`, `writeLine`, `Write`)**: How the `Terminal` sends data back to the underlying `io.ReadWriter`. The `Write` method's logic for clearing the screen and redrawing is complex and worth noting.
* **`ReadLine`**:  The main function for reading user input. It orchestrates the reading of bytes, converting them to keys, handling the keys, and managing the history. The logic around `pasteActive` and `ErrPasteIndicator` is a key feature.
* **`ReadPassword`**: A specialized version of `ReadLine` that disables echoing.
* **`SetSize`**:  Handles terminal resizing, and the comments highlight the complexities of different terminal behaviors.
* **`SetBracketedPasteMode`**:  Enables/disables bracketed paste, which is relevant to security and data integrity.
* **`stRingBuffer`**:  A simple ring buffer for storing command history.

**4. Identifying Functionality and Go Feature Demonstration:**

Based on the code and method names, I can now list the functionalities:

* **Basic Terminal Emulation:** Reading input, writing output.
* **Input Editing:** Backspace, cursor movement (left, right, home, end), deleting words/lines.
* **History:**  Recalling previous commands using up/down arrows.
* **Auto-completion:** Using a callback function to suggest completions.
* **Password Input:** Reading input without echoing.
* **Prompt Handling:** Displaying a prompt before input.
* **Terminal Resizing:** Handling changes in terminal dimensions.
* **Bracketed Paste Mode:**  Distinguishing pasted text from typed text.
* **Escape Code Handling:**  Using escape sequences for basic text formatting.

To demonstrate these with Go code, I think about simple use cases for each:

* **Basic Input/Output:** Reading a line and printing it back.
* **Password Input:** Reading a password securely.
* **Auto-completion:**  Creating a simple auto-completer.
* **History:**  Demonstrating navigating through history.
* **Bracketed Paste:**  Showing how the error is returned for pasted content.
* **Resizing:** Simulating a resize event (though this is harder to demo directly without a real terminal).

**5. Code Example Construction (Iterative Process):**

For each demonstration, I start with a basic structure and then add the necessary `term` package usage. I focus on clarity and showing the core concept. I also consider what input would be relevant to trigger the behavior.

* **Initial thought for Auto-completion:** Just a function that checks if the input starts with a prefix.
* **Refinement:**  Make it return a replacement and new cursor position, as defined by the `AutoCompleteCallback` signature.

**6. Identifying Error-Prone Areas:**

I review the code for potential pitfalls:

* **Incorrect `io.ReadWriter` Setup:**  Emphasize the need for raw mode for local terminals.
* **Assuming Terminal Support:**  Highlight that not all terminals support all features (e.g., bracketed paste).
* **Concurrency:** Mention the `sync.Mutex` and the importance of not interfering with the terminal's internal state.
* **Handling `ErrPasteIndicator`:**  Explain why ignoring this error could lead to incorrect handling of pasted data.

**7. Structuring the Output:**

Finally, I organize the information logically, starting with the functionalities, then the Go feature demonstrations with clear examples (including expected input and output), followed by explanations of command-line argument handling (though this code doesn't directly process them), and finally, the common mistakes. I use code blocks for examples and clear, concise explanations.

This iterative process of understanding, analyzing, demonstrating, and considering potential issues allows for a comprehensive analysis of the provided code snippet.
这段代码是 Go 语言 `golang.org/x/term` 库中 `terminal.go` 文件的一部分，它实现了与终端交互的核心功能，特别是针对 VT100 终端的模拟和控制。

以下是它主要的功能列表：

1. **终端状态管理:**
   - 维护当前终端的状态，包括光标位置 (`cursorX`, `cursorY`), 终端尺寸 (`termWidth`, `termHeight`), 当前输入行 (`line`), 光标在行中的位置 (`pos`), 是否开启回显 (`echo`), 以及是否处于粘贴模式 (`pasteActive`)。

2. **输入处理:**
   - 从 `io.ReadWriter` 接口读取终端输入。
   - 将读取到的字节序列转换为按键事件 (`bytesToKey` 函数负责解析复杂的转义序列）。
   - 处理各种按键事件，包括：
     - 字符输入和删除 (退格键)。
     - 光标移动 (上下左右，行首行尾)。
     - 单词和行删除。
     - 历史命令浏览 (上下箭头)。
     - 清屏。
     - Ctrl+C 和 Ctrl+D 等控制键。
     - 粘贴开始和结束事件（用于 bracketed paste mode）。

3. **输出处理:**
   - 管理一个输出缓冲区 (`outBuf`)，用于存储要发送到终端的控制序列和字符。
   - 提供方法向缓冲区添加数据 (`queue`)。
   - 提供移动光标的方法 (`moveCursorToPos`, `move`)。
   - 提供清除行内容的方法 (`clearLineToRight`)。
   - 提供写入一行内容的方法 (`writeLine`)，并处理自动换行。
   - `Write` 方法接收任意 `[]byte` 数据，并将其安全地写入终端，同时处理可能存在的用户输入和提示符。

4. **自动补全:**
   - 提供 `AutoCompleteCallback` 字段，允许使用者注册一个回调函数，在用户输入时提供自动补全功能。

5. **命令历史记录:**
   - 使用环形缓冲区 (`stRingBuffer`) 存储用户输入的历史命令。

6. **密码输入:**
   - 提供 `ReadPassword` 方法，读取用户输入的密码，禁止回显。

7. **终端尺寸管理:**
   - 提供 `SetSize` 方法，允许外部设置终端的宽度和高度，并相应地调整终端状态和屏幕显示。

8. **Bracketed Paste Mode:**
   - 提供 `SetBracketedPasteMode` 方法，允许启用或禁用 bracketed paste mode，该模式下粘贴的内容会被特殊标记，可以区分是用户输入还是粘贴的内容。

**它是什么go语言功能的实现？**

这段代码主要实现了 **伪终端 (Pseudo-Terminal)** 或者说是 **行编辑 (Line Editor)** 的功能。它不是一个完整的终端模拟器，但它提供了一种在程序中与用户进行行式交互的方式，类似于 shell 的输入行。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/term"
)

func main() {
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalf("Could not enter raw mode: %v", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	t := term.NewTerminal(os.Stdin, "> ")

	// 设置自动补全回调
	t.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
		if key == ' ' { // 以空格触发补全
			if line == "hel" {
				return "hello ", 6, true
			}
		}
		return "", 0, false
	}

	for {
		line, err := t.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Error reading line: %v", err)
		}
		fmt.Printf("You entered: %s\n", line)
	}
}
```

**假设的输入与输出:**

假设在上面的代码运行时，用户输入 "hel" 然后按下空格键，由于设置了自动补全回调，预期输出如下：

**输入:** `hel ` (按下空格后)

**输出:**  终端会显示 "hello "，光标移动到 "o" 后面。

如果用户接着输入 "world"，然后按下回车键，则会输出：

**输入:** `helloworld` (按下回车)

**输出:**
```
You entered: helloworld
```

**涉及命令行参数的具体处理:**

这段代码本身**不直接处理**命令行参数。它主要关注终端的输入和输出。命令行参数的处理通常发生在 `main` 函数或其他初始化阶段，与终端交互是独立的。

**使用者易犯错的点:**

1. **没有将终端设置为 raw 模式:**
   - 在 Unix-like 系统上，如果直接使用 `os.Stdin` 和 `os.Stdout` 创建 `Terminal` 实例，终端可能不会按预期工作。例如，输入会被缓冲，控制字符不会被正确解释。
   - **错误示例:**
     ```go
     t := term.NewTerminal(os.Stdin, "> ") // 可能会有问题
     ```
   - **正确做法:**
     ```go
     oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
     // ... 错误处理 ...
     defer term.Restore(int(os.Stdin.Fd()), oldState)
     t := term.NewTerminal(os.Stdin, "> ")
     ```

2. **假设所有终端都支持 VT100 转义序列:**
   - 代码中硬编码了 `vt100EscapeCodes`。虽然 VT100 是一个很常见的标准，但并不是所有终端都完全兼容。在一些特殊终端上，颜色或光标控制可能无法正常工作。

3. **在 `AutoCompleteCallback` 中进行耗时操作:**
   - `AutoCompleteCallback` 在每次按键时都会被调用。如果回调函数执行时间过长，会阻塞终端的输入处理，导致界面卡顿。
   - **错误示例:**
     ```go
     t.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
         // 模拟耗时操作
         time.Sleep(1 * time.Second)
         // ... 补全逻辑 ...
         return
     }
     ```
   - **建议:**  `AutoCompleteCallback` 应该快速返回。如果需要进行复杂的查找或计算，可以考虑使用 Goroutine 或者异步处理。

4. **不正确处理 `ErrPasteIndicator`:**
   - 当 bracketed paste mode 启用时，如果用户粘贴了内容，`ReadLine` 可能会返回 `ErrPasteIndicator` 错误。使用者需要根据这个错误来区分粘贴的内容和用户手动输入的内容，以便进行不同的处理。
   - **错误示例:**
     ```go
     line, err := t.ReadLine()
     if err != nil { // 没有区分 ErrPasteIndicator
         log.Println("Error reading line:", err)
         continue
     }
     ```
   - **正确做法:**
     ```go
     line, err := t.ReadLine()
     if err != nil {
         if err == term.ErrPasteIndicator {
             log.Println("Pasted content:", line)
         } else {
             log.Println("Error reading line:", err)
         }
         continue
     }
     log.Println("You entered:", line)
     ```

总而言之，这段代码实现了一个功能强大的终端交互组件，但使用者需要了解终端的工作原理和库的使用细节，才能避免一些常见的错误。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/term/terminal.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package term

import (
	"bytes"
	"io"
	"runtime"
	"strconv"
	"sync"
	"unicode/utf8"
)

// EscapeCodes contains escape sequences that can be written to the terminal in
// order to achieve different styles of text.
type EscapeCodes struct {
	// Foreground colors
	Black, Red, Green, Yellow, Blue, Magenta, Cyan, White []byte

	// Reset all attributes
	Reset []byte
}

var vt100EscapeCodes = EscapeCodes{
	Black:   []byte{keyEscape, '[', '3', '0', 'm'},
	Red:     []byte{keyEscape, '[', '3', '1', 'm'},
	Green:   []byte{keyEscape, '[', '3', '2', 'm'},
	Yellow:  []byte{keyEscape, '[', '3', '3', 'm'},
	Blue:    []byte{keyEscape, '[', '3', '4', 'm'},
	Magenta: []byte{keyEscape, '[', '3', '5', 'm'},
	Cyan:    []byte{keyEscape, '[', '3', '6', 'm'},
	White:   []byte{keyEscape, '[', '3', '7', 'm'},

	Reset: []byte{keyEscape, '[', '0', 'm'},
}

// Terminal contains the state for running a VT100 terminal that is capable of
// reading lines of input.
type Terminal struct {
	// AutoCompleteCallback, if non-null, is called for each keypress with
	// the full input line and the current position of the cursor (in
	// bytes, as an index into |line|). If it returns ok=false, the key
	// press is processed normally. Otherwise it returns a replacement line
	// and the new cursor position.
	AutoCompleteCallback func(line string, pos int, key rune) (newLine string, newPos int, ok bool)

	// Escape contains a pointer to the escape codes for this terminal.
	// It's always a valid pointer, although the escape codes themselves
	// may be empty if the terminal doesn't support them.
	Escape *EscapeCodes

	// lock protects the terminal and the state in this object from
	// concurrent processing of a key press and a Write() call.
	lock sync.Mutex

	c      io.ReadWriter
	prompt []rune

	// line is the current line being entered.
	line []rune
	// pos is the logical position of the cursor in line
	pos int
	// echo is true if local echo is enabled
	echo bool
	// pasteActive is true iff there is a bracketed paste operation in
	// progress.
	pasteActive bool

	// cursorX contains the current X value of the cursor where the left
	// edge is 0. cursorY contains the row number where the first row of
	// the current line is 0.
	cursorX, cursorY int
	// maxLine is the greatest value of cursorY so far.
	maxLine int

	termWidth, termHeight int

	// outBuf contains the terminal data to be sent.
	outBuf []byte
	// remainder contains the remainder of any partial key sequences after
	// a read. It aliases into inBuf.
	remainder []byte
	inBuf     [256]byte

	// history contains previously entered commands so that they can be
	// accessed with the up and down keys.
	history stRingBuffer
	// historyIndex stores the currently accessed history entry, where zero
	// means the immediately previous entry.
	historyIndex int
	// When navigating up and down the history it's possible to return to
	// the incomplete, initial line. That value is stored in
	// historyPending.
	historyPending string
}

// NewTerminal runs a VT100 terminal on the given ReadWriter. If the ReadWriter is
// a local terminal, that terminal must first have been put into raw mode.
// prompt is a string that is written at the start of each input line (i.e.
// "> ").
func NewTerminal(c io.ReadWriter, prompt string) *Terminal {
	return &Terminal{
		Escape:       &vt100EscapeCodes,
		c:            c,
		prompt:       []rune(prompt),
		termWidth:    80,
		termHeight:   24,
		echo:         true,
		historyIndex: -1,
	}
}

const (
	keyCtrlC     = 3
	keyCtrlD     = 4
	keyCtrlU     = 21
	keyEnter     = '\r'
	keyEscape    = 27
	keyBackspace = 127
	keyUnknown   = 0xd800 /* UTF-16 surrogate area */ + iota
	keyUp
	keyDown
	keyLeft
	keyRight
	keyAltLeft
	keyAltRight
	keyHome
	keyEnd
	keyDeleteWord
	keyDeleteLine
	keyClearScreen
	keyPasteStart
	keyPasteEnd
)

var (
	crlf       = []byte{'\r', '\n'}
	pasteStart = []byte{keyEscape, '[', '2', '0', '0', '~'}
	pasteEnd   = []byte{keyEscape, '[', '2', '0', '1', '~'}
)

// bytesToKey tries to parse a key sequence from b. If successful, it returns
// the key and the remainder of the input. Otherwise it returns utf8.RuneError.
func bytesToKey(b []byte, pasteActive bool) (rune, []byte) {
	if len(b) == 0 {
		return utf8.RuneError, nil
	}

	if !pasteActive {
		switch b[0] {
		case 1: // ^A
			return keyHome, b[1:]
		case 2: // ^B
			return keyLeft, b[1:]
		case 5: // ^E
			return keyEnd, b[1:]
		case 6: // ^F
			return keyRight, b[1:]
		case 8: // ^H
			return keyBackspace, b[1:]
		case 11: // ^K
			return keyDeleteLine, b[1:]
		case 12: // ^L
			return keyClearScreen, b[1:]
		case 23: // ^W
			return keyDeleteWord, b[1:]
		case 14: // ^N
			return keyDown, b[1:]
		case 16: // ^P
			return keyUp, b[1:]
		}
	}

	if b[0] != keyEscape {
		if !utf8.FullRune(b) {
			return utf8.RuneError, b
		}
		r, l := utf8.DecodeRune(b)
		return r, b[l:]
	}

	if !pasteActive && len(b) >= 3 && b[0] == keyEscape && b[1] == '[' {
		switch b[2] {
		case 'A':
			return keyUp, b[3:]
		case 'B':
			return keyDown, b[3:]
		case 'C':
			return keyRight, b[3:]
		case 'D':
			return keyLeft, b[3:]
		case 'H':
			return keyHome, b[3:]
		case 'F':
			return keyEnd, b[3:]
		}
	}

	if !pasteActive && len(b) >= 6 && b[0] == keyEscape && b[1] == '[' && b[2] == '1' && b[3] == ';' && b[4] == '3' {
		switch b[5] {
		case 'C':
			return keyAltRight, b[6:]
		case 'D':
			return keyAltLeft, b[6:]
		}
	}

	if !pasteActive && len(b) >= 6 && bytes.Equal(b[:6], pasteStart) {
		return keyPasteStart, b[6:]
	}

	if pasteActive && len(b) >= 6 && bytes.Equal(b[:6], pasteEnd) {
		return keyPasteEnd, b[6:]
	}

	// If we get here then we have a key that we don't recognise, or a
	// partial sequence. It's not clear how one should find the end of a
	// sequence without knowing them all, but it seems that [a-zA-Z~] only
	// appears at the end of a sequence.
	for i, c := range b[0:] {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '~' {
			return keyUnknown, b[i+1:]
		}
	}

	return utf8.RuneError, b
}

// queue appends data to the end of t.outBuf
func (t *Terminal) queue(data []rune) {
	t.outBuf = append(t.outBuf, []byte(string(data))...)
}

var space = []rune{' '}

func isPrintable(key rune) bool {
	isInSurrogateArea := key >= 0xd800 && key <= 0xdbff
	return key >= 32 && !isInSurrogateArea
}

// moveCursorToPos appends data to t.outBuf which will move the cursor to the
// given, logical position in the text.
func (t *Terminal) moveCursorToPos(pos int) {
	if !t.echo {
		return
	}

	x := visualLength(t.prompt) + pos
	y := x / t.termWidth
	x = x % t.termWidth

	up := 0
	if y < t.cursorY {
		up = t.cursorY - y
	}

	down := 0
	if y > t.cursorY {
		down = y - t.cursorY
	}

	left := 0
	if x < t.cursorX {
		left = t.cursorX - x
	}

	right := 0
	if x > t.cursorX {
		right = x - t.cursorX
	}

	t.cursorX = x
	t.cursorY = y
	t.move(up, down, left, right)
}

func (t *Terminal) move(up, down, left, right int) {
	m := []rune{}

	// 1 unit up can be expressed as ^[[A or ^[A
	// 5 units up can be expressed as ^[[5A

	if up == 1 {
		m = append(m, keyEscape, '[', 'A')
	} else if up > 1 {
		m = append(m, keyEscape, '[')
		m = append(m, []rune(strconv.Itoa(up))...)
		m = append(m, 'A')
	}

	if down == 1 {
		m = append(m, keyEscape, '[', 'B')
	} else if down > 1 {
		m = append(m, keyEscape, '[')
		m = append(m, []rune(strconv.Itoa(down))...)
		m = append(m, 'B')
	}

	if right == 1 {
		m = append(m, keyEscape, '[', 'C')
	} else if right > 1 {
		m = append(m, keyEscape, '[')
		m = append(m, []rune(strconv.Itoa(right))...)
		m = append(m, 'C')
	}

	if left == 1 {
		m = append(m, keyEscape, '[', 'D')
	} else if left > 1 {
		m = append(m, keyEscape, '[')
		m = append(m, []rune(strconv.Itoa(left))...)
		m = append(m, 'D')
	}

	t.queue(m)
}

func (t *Terminal) clearLineToRight() {
	op := []rune{keyEscape, '[', 'K'}
	t.queue(op)
}

const maxLineLength = 4096

func (t *Terminal) setLine(newLine []rune, newPos int) {
	if t.echo {
		t.moveCursorToPos(0)
		t.writeLine(newLine)
		for i := len(newLine); i < len(t.line); i++ {
			t.writeLine(space)
		}
		t.moveCursorToPos(newPos)
	}
	t.line = newLine
	t.pos = newPos
}

func (t *Terminal) advanceCursor(places int) {
	t.cursorX += places
	t.cursorY += t.cursorX / t.termWidth
	if t.cursorY > t.maxLine {
		t.maxLine = t.cursorY
	}
	t.cursorX = t.cursorX % t.termWidth

	if places > 0 && t.cursorX == 0 {
		// Normally terminals will advance the current position
		// when writing a character. But that doesn't happen
		// for the last character in a line. However, when
		// writing a character (except a new line) that causes
		// a line wrap, the position will be advanced two
		// places.
		//
		// So, if we are stopping at the end of a line, we
		// need to write a newline so that our cursor can be
		// advanced to the next line.
		t.outBuf = append(t.outBuf, '\r', '\n')
	}
}

func (t *Terminal) eraseNPreviousChars(n int) {
	if n == 0 {
		return
	}

	if t.pos < n {
		n = t.pos
	}
	t.pos -= n
	t.moveCursorToPos(t.pos)

	copy(t.line[t.pos:], t.line[n+t.pos:])
	t.line = t.line[:len(t.line)-n]
	if t.echo {
		t.writeLine(t.line[t.pos:])
		for i := 0; i < n; i++ {
			t.queue(space)
		}
		t.advanceCursor(n)
		t.moveCursorToPos(t.pos)
	}
}

// countToLeftWord returns then number of characters from the cursor to the
// start of the previous word.
func (t *Terminal) countToLeftWord() int {
	if t.pos == 0 {
		return 0
	}

	pos := t.pos - 1
	for pos > 0 {
		if t.line[pos] != ' ' {
			break
		}
		pos--
	}
	for pos > 0 {
		if t.line[pos] == ' ' {
			pos++
			break
		}
		pos--
	}

	return t.pos - pos
}

// countToRightWord returns then number of characters from the cursor to the
// start of the next word.
func (t *Terminal) countToRightWord() int {
	pos := t.pos
	for pos < len(t.line) {
		if t.line[pos] == ' ' {
			break
		}
		pos++
	}
	for pos < len(t.line) {
		if t.line[pos] != ' ' {
			break
		}
		pos++
	}
	return pos - t.pos
}

// visualLength returns the number of visible glyphs in s.
func visualLength(runes []rune) int {
	inEscapeSeq := false
	length := 0

	for _, r := range runes {
		switch {
		case inEscapeSeq:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscapeSeq = false
			}
		case r == '\x1b':
			inEscapeSeq = true
		default:
			length++
		}
	}

	return length
}

// handleKey processes the given key and, optionally, returns a line of text
// that the user has entered.
func (t *Terminal) handleKey(key rune) (line string, ok bool) {
	if t.pasteActive && key != keyEnter {
		t.addKeyToLine(key)
		return
	}

	switch key {
	case keyBackspace:
		if t.pos == 0 {
			return
		}
		t.eraseNPreviousChars(1)
	case keyAltLeft:
		// move left by a word.
		t.pos -= t.countToLeftWord()
		t.moveCursorToPos(t.pos)
	case keyAltRight:
		// move right by a word.
		t.pos += t.countToRightWord()
		t.moveCursorToPos(t.pos)
	case keyLeft:
		if t.pos == 0 {
			return
		}
		t.pos--
		t.moveCursorToPos(t.pos)
	case keyRight:
		if t.pos == len(t.line) {
			return
		}
		t.pos++
		t.moveCursorToPos(t.pos)
	case keyHome:
		if t.pos == 0 {
			return
		}
		t.pos = 0
		t.moveCursorToPos(t.pos)
	case keyEnd:
		if t.pos == len(t.line) {
			return
		}
		t.pos = len(t.line)
		t.moveCursorToPos(t.pos)
	case keyUp:
		entry, ok := t.history.NthPreviousEntry(t.historyIndex + 1)
		if !ok {
			return "", false
		}
		if t.historyIndex == -1 {
			t.historyPending = string(t.line)
		}
		t.historyIndex++
		runes := []rune(entry)
		t.setLine(runes, len(runes))
	case keyDown:
		switch t.historyIndex {
		case -1:
			return
		case 0:
			runes := []rune(t.historyPending)
			t.setLine(runes, len(runes))
			t.historyIndex--
		default:
			entry, ok := t.history.NthPreviousEntry(t.historyIndex - 1)
			if ok {
				t.historyIndex--
				runes := []rune(entry)
				t.setLine(runes, len(runes))
			}
		}
	case keyEnter:
		t.moveCursorToPos(len(t.line))
		t.queue([]rune("\r\n"))
		line = string(t.line)
		ok = true
		t.line = t.line[:0]
		t.pos = 0
		t.cursorX = 0
		t.cursorY = 0
		t.maxLine = 0
	case keyDeleteWord:
		// Delete zero or more spaces and then one or more characters.
		t.eraseNPreviousChars(t.countToLeftWord())
	case keyDeleteLine:
		// Delete everything from the current cursor position to the
		// end of line.
		for i := t.pos; i < len(t.line); i++ {
			t.queue(space)
			t.advanceCursor(1)
		}
		t.line = t.line[:t.pos]
		t.moveCursorToPos(t.pos)
	case keyCtrlD:
		// Erase the character under the current position.
		// The EOF case when the line is empty is handled in
		// readLine().
		if t.pos < len(t.line) {
			t.pos++
			t.eraseNPreviousChars(1)
		}
	case keyCtrlU:
		t.eraseNPreviousChars(t.pos)
	case keyClearScreen:
		// Erases the screen and moves the cursor to the home position.
		t.queue([]rune("\x1b[2J\x1b[H"))
		t.queue(t.prompt)
		t.cursorX, t.cursorY = 0, 0
		t.advanceCursor(visualLength(t.prompt))
		t.setLine(t.line, t.pos)
	default:
		if t.AutoCompleteCallback != nil {
			prefix := string(t.line[:t.pos])
			suffix := string(t.line[t.pos:])

			t.lock.Unlock()
			newLine, newPos, completeOk := t.AutoCompleteCallback(prefix+suffix, len(prefix), key)
			t.lock.Lock()

			if completeOk {
				t.setLine([]rune(newLine), utf8.RuneCount([]byte(newLine)[:newPos]))
				return
			}
		}
		if !isPrintable(key) {
			return
		}
		if len(t.line) == maxLineLength {
			return
		}
		t.addKeyToLine(key)
	}
	return
}

// addKeyToLine inserts the given key at the current position in the current
// line.
func (t *Terminal) addKeyToLine(key rune) {
	if len(t.line) == cap(t.line) {
		newLine := make([]rune, len(t.line), 2*(1+len(t.line)))
		copy(newLine, t.line)
		t.line = newLine
	}
	t.line = t.line[:len(t.line)+1]
	copy(t.line[t.pos+1:], t.line[t.pos:])
	t.line[t.pos] = key
	if t.echo {
		t.writeLine(t.line[t.pos:])
	}
	t.pos++
	t.moveCursorToPos(t.pos)
}

func (t *Terminal) writeLine(line []rune) {
	for len(line) != 0 {
		remainingOnLine := t.termWidth - t.cursorX
		todo := len(line)
		if todo > remainingOnLine {
			todo = remainingOnLine
		}
		t.queue(line[:todo])
		t.advanceCursor(visualLength(line[:todo]))
		line = line[todo:]
	}
}

// writeWithCRLF writes buf to w but replaces all occurrences of \n with \r\n.
func writeWithCRLF(w io.Writer, buf []byte) (n int, err error) {
	for len(buf) > 0 {
		i := bytes.IndexByte(buf, '\n')
		todo := len(buf)
		if i >= 0 {
			todo = i
		}

		var nn int
		nn, err = w.Write(buf[:todo])
		n += nn
		if err != nil {
			return n, err
		}
		buf = buf[todo:]

		if i >= 0 {
			if _, err = w.Write(crlf); err != nil {
				return n, err
			}
			n++
			buf = buf[1:]
		}
	}

	return n, nil
}

func (t *Terminal) Write(buf []byte) (n int, err error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.cursorX == 0 && t.cursorY == 0 {
		// This is the easy case: there's nothing on the screen that we
		// have to move out of the way.
		return writeWithCRLF(t.c, buf)
	}

	// We have a prompt and possibly user input on the screen. We
	// have to clear it first.
	t.move(0 /* up */, 0 /* down */, t.cursorX /* left */, 0 /* right */)
	t.cursorX = 0
	t.clearLineToRight()

	for t.cursorY > 0 {
		t.move(1 /* up */, 0, 0, 0)
		t.cursorY--
		t.clearLineToRight()
	}

	if _, err = t.c.Write(t.outBuf); err != nil {
		return
	}
	t.outBuf = t.outBuf[:0]

	if n, err = writeWithCRLF(t.c, buf); err != nil {
		return
	}

	t.writeLine(t.prompt)
	if t.echo {
		t.writeLine(t.line)
	}

	t.moveCursorToPos(t.pos)

	if _, err = t.c.Write(t.outBuf); err != nil {
		return
	}
	t.outBuf = t.outBuf[:0]
	return
}

// ReadPassword temporarily changes the prompt and reads a password, without
// echo, from the terminal.
func (t *Terminal) ReadPassword(prompt string) (line string, err error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	oldPrompt := t.prompt
	t.prompt = []rune(prompt)
	t.echo = false

	line, err = t.readLine()

	t.prompt = oldPrompt
	t.echo = true

	return
}

// ReadLine returns a line of input from the terminal.
func (t *Terminal) ReadLine() (line string, err error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.readLine()
}

func (t *Terminal) readLine() (line string, err error) {
	// t.lock must be held at this point

	if t.cursorX == 0 && t.cursorY == 0 {
		t.writeLine(t.prompt)
		t.c.Write(t.outBuf)
		t.outBuf = t.outBuf[:0]
	}

	lineIsPasted := t.pasteActive

	for {
		rest := t.remainder
		lineOk := false
		for !lineOk {
			var key rune
			key, rest = bytesToKey(rest, t.pasteActive)
			if key == utf8.RuneError {
				break
			}
			if !t.pasteActive {
				if key == keyCtrlD {
					if len(t.line) == 0 {
						return "", io.EOF
					}
				}
				if key == keyCtrlC {
					return "", io.EOF
				}
				if key == keyPasteStart {
					t.pasteActive = true
					if len(t.line) == 0 {
						lineIsPasted = true
					}
					continue
				}
			} else if key == keyPasteEnd {
				t.pasteActive = false
				continue
			}
			if !t.pasteActive {
				lineIsPasted = false
			}
			line, lineOk = t.handleKey(key)
		}
		if len(rest) > 0 {
			n := copy(t.inBuf[:], rest)
			t.remainder = t.inBuf[:n]
		} else {
			t.remainder = nil
		}
		t.c.Write(t.outBuf)
		t.outBuf = t.outBuf[:0]
		if lineOk {
			if t.echo {
				t.historyIndex = -1
				t.history.Add(line)
			}
			if lineIsPasted {
				err = ErrPasteIndicator
			}
			return
		}

		// t.remainder is a slice at the beginning of t.inBuf
		// containing a partial key sequence
		readBuf := t.inBuf[len(t.remainder):]
		var n int

		t.lock.Unlock()
		n, err = t.c.Read(readBuf)
		t.lock.Lock()

		if err != nil {
			return
		}

		t.remainder = t.inBuf[:n+len(t.remainder)]
	}
}

// SetPrompt sets the prompt to be used when reading subsequent lines.
func (t *Terminal) SetPrompt(prompt string) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.prompt = []rune(prompt)
}

func (t *Terminal) clearAndRepaintLinePlusNPrevious(numPrevLines int) {
	// Move cursor to column zero at the start of the line.
	t.move(t.cursorY, 0, t.cursorX, 0)
	t.cursorX, t.cursorY = 0, 0
	t.clearLineToRight()
	for t.cursorY < numPrevLines {
		// Move down a line
		t.move(0, 1, 0, 0)
		t.cursorY++
		t.clearLineToRight()
	}
	// Move back to beginning.
	t.move(t.cursorY, 0, 0, 0)
	t.cursorX, t.cursorY = 0, 0

	t.queue(t.prompt)
	t.advanceCursor(visualLength(t.prompt))
	t.writeLine(t.line)
	t.moveCursorToPos(t.pos)
}

func (t *Terminal) SetSize(width, height int) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if width == 0 {
		width = 1
	}

	oldWidth := t.termWidth
	t.termWidth, t.termHeight = width, height

	switch {
	case width == oldWidth:
		// If the width didn't change then nothing else needs to be
		// done.
		return nil
	case len(t.line) == 0 && t.cursorX == 0 && t.cursorY == 0:
		// If there is nothing on current line and no prompt printed,
		// just do nothing
		return nil
	case width < oldWidth:
		// Some terminals (e.g. xterm) will truncate lines that were
		// too long when shinking. Others, (e.g. gnome-terminal) will
		// attempt to wrap them. For the former, repainting t.maxLine
		// works great, but that behaviour goes badly wrong in the case
		// of the latter because they have doubled every full line.

		// We assume that we are working on a terminal that wraps lines
		// and adjust the cursor position based on every previous line
		// wrapping and turning into two. This causes the prompt on
		// xterms to move upwards, which isn't great, but it avoids a
		// huge mess with gnome-terminal.
		if t.cursorX >= t.termWidth {
			t.cursorX = t.termWidth - 1
		}
		t.cursorY *= 2
		t.clearAndRepaintLinePlusNPrevious(t.maxLine * 2)
	case width > oldWidth:
		// If the terminal expands then our position calculations will
		// be wrong in the future because we think the cursor is
		// |t.pos| chars into the string, but there will be a gap at
		// the end of any wrapped line.
		//
		// But the position will actually be correct until we move, so
		// we can move back to the beginning and repaint everything.
		t.clearAndRepaintLinePlusNPrevious(t.maxLine)
	}

	_, err := t.c.Write(t.outBuf)
	t.outBuf = t.outBuf[:0]
	return err
}

type pasteIndicatorError struct{}

func (pasteIndicatorError) Error() string {
	return "terminal: ErrPasteIndicator not correctly handled"
}

// ErrPasteIndicator may be returned from ReadLine as the error, in addition
// to valid line data. It indicates that bracketed paste mode is enabled and
// that the returned line consists only of pasted data. Programs may wish to
// interpret pasted data more literally than typed data.
var ErrPasteIndicator = pasteIndicatorError{}

// SetBracketedPasteMode requests that the terminal bracket paste operations
// with markers. Not all terminals support this but, if it is supported, then
// enabling this mode will stop any autocomplete callback from running due to
// pastes. Additionally, any lines that are completely pasted will be returned
// from ReadLine with the error set to ErrPasteIndicator.
func (t *Terminal) SetBracketedPasteMode(on bool) {
	if on {
		io.WriteString(t.c, "\x1b[?2004h")
	} else {
		io.WriteString(t.c, "\x1b[?2004l")
	}
}

// stRingBuffer is a ring buffer of strings.
type stRingBuffer struct {
	// entries contains max elements.
	entries []string
	max     int
	// head contains the index of the element most recently added to the ring.
	head int
	// size contains the number of elements in the ring.
	size int
}

func (s *stRingBuffer) Add(a string) {
	if s.entries == nil {
		const defaultNumEntries = 100
		s.entries = make([]string, defaultNumEntries)
		s.max = defaultNumEntries
	}

	s.head = (s.head + 1) % s.max
	s.entries[s.head] = a
	if s.size < s.max {
		s.size++
	}
}

// NthPreviousEntry returns the value passed to the nth previous call to Add.
// If n is zero then the immediately prior value is returned, if one, then the
// next most recent, and so on. If such an element doesn't exist then ok is
// false.
func (s *stRingBuffer) NthPreviousEntry(n int) (value string, ok bool) {
	if n < 0 || n >= s.size {
		return "", false
	}
	index := s.head - n
	if index < 0 {
		index += s.max
	}
	return s.entries[index], true
}

// readPasswordLine reads from reader until it finds \n or io.EOF.
// The slice returned does not include the \n.
// readPasswordLine also ignores any \r it finds.
// Windows uses \r as end of line. So, on Windows, readPasswordLine
// reads until it finds \r and ignores any \n it finds during processing.
func readPasswordLine(reader io.Reader) ([]byte, error) {
	var buf [1]byte
	var ret []byte

	for {
		n, err := reader.Read(buf[:])
		if n > 0 {
			switch buf[0] {
			case '\b':
				if len(ret) > 0 {
					ret = ret[:len(ret)-1]
				}
			case '\n':
				if runtime.GOOS != "windows" {
					return ret, nil
				}
				// otherwise ignore \n
			case '\r':
				if runtime.GOOS == "windows" {
					return ret, nil
				}
				// otherwise ignore \r
			default:
				ret = append(ret, buf[0])
			}
			continue
		}
		if err != nil {
			if err == io.EOF && len(ret) > 0 {
				return ret, nil
			}
			return ret, err
		}
	}
}

"""



```