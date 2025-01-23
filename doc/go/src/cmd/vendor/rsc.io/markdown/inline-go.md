Response:
Let's break down the thought process for analyzing the Go code snippet.

1. **Understanding the Goal:** The request asks for a functional breakdown of the provided Go code, specifically focusing on its role in Markdown parsing, illustrating its features with examples, considering command-line arguments (if any), and highlighting potential pitfalls for users.

2. **Initial Code Scan and Identification of Key Structures:**  A quick skim reveals several important elements:
    * **Package Declaration:** `package markdown` -  Indicates this code is part of a Markdown processing library.
    * **Imports:** `bytes`, `fmt`, `strings`, `unicode`, `unicode/utf8` -  These suggest string manipulation, HTML escaping, and Unicode handling, all common in text processing.
    * **`Inline` Interface:**  This is a core concept, defining methods for different output formats (HTML, Text, Markdown). This hints at a system for representing inline elements.
    * **Concrete Types Implementing `Inline`:** `Plain`, `Code`, `Strong`, `Emph`, `Link`, `Image`, `Del`, `Escaped`, `Emoji`. These are the different types of inline Markdown elements the code handles.
    * **`parseState` Struct:** This structure likely holds the state during the parsing process. The `inline` method and associated helper functions strongly suggest this.
    * **Parsing Functions:**  Functions like `parseEscape`, `parseCodeSpan`, `parseLinkOpen`, `parseEmph`, etc., are clearly responsible for identifying and processing different Markdown syntax.
    * **Emphasis Processing Logic:** The comments and the `emph` function point to a potentially complex algorithm for handling emphasis (bold, italics, strikethrough).

3. **Dissecting Core Functionality - Inline Elements:**
    * **Identify the `Inline` interface:** Note its purpose of providing different rendering methods.
    * **Examine each concrete type:** Understand what each represents (`Plain` for regular text, `Code` for code blocks, `Strong` for bold, etc.) and how their `PrintHTML`, `PrintText`, and `printMarkdown` methods work. This will directly address the "功能" aspect.

4. **Tracing the Parsing Process:**
    * **Focus on the `inline` method:**  Recognize this as the entry point for parsing a string into a list of `Inline` elements.
    * **Analyze the `switch` statement in `inline`:**  This reveals the different characters that trigger specific parsing logic.
    * **Examine individual parsing functions:** Understand how each function identifies and creates the corresponding `Inline` element. For example, `parseCodeSpan` looks for backticks, `parseLinkOpen` for `[`, etc.
    * **Pay attention to the handling of `[` and `]` for links:** The logic involving the `opens` stack and the call to `parseLinkClose` is crucial for understanding link parsing.
    * **Delve into the `emph` function:**  This is more involved. The use of a stack (`stack`) to manage potential openers and closers of emphasis markers is a key detail. The nested loops and conditions within `emph` implement the logic for matching delimiters.

5. **Illustrative Examples with Go Code:**
    * **Start with simple cases:**  Demonstrate `Plain`, `Code`, `Emph`, `Strong`.
    * **Show more complex cases:**  Illustrate links, images, and how nested emphasis might work (even if the example doesn't fully replicate the complex logic, it gives a basic idea).
    * **Include the necessary setup:** Show how to create a `parseState` and call the `inline` method.
    * **Provide example input and the expected output (conceptually or literally).**

6. **Reasoning about Go Language Features:**
    * **Interfaces:** The `Inline` interface is a prime example.
    * **Structs:**  The various `Inline` implementations and `parseState`.
    * **Methods on Structs:** The `PrintHTML`, `PrintText`, `printMarkdown` methods.
    * **String Manipulation:**  Functions from the `strings` package are heavily used.
    * **Unicode Handling:**  The `unicode` and `unicode/utf8` packages.

7. **Considering Command-Line Arguments:**  A careful examination of the code reveals *no* direct handling of command-line arguments within the provided snippet. State this explicitly.

8. **Identifying Potential User Errors:**
    * **Focus on the complexity of the emphasis parsing:**  Mismatched or improperly nested emphasis markers are likely to cause unexpected results. Provide examples of these.
    * **Mention the intricacies of link syntax:** Incorrectly formed links or missing labels for reference links are common errors.

9. **Structuring the Answer:** Organize the information logically with clear headings for "功能", "实现的 Go 语言功能", "代码举例", "命令行参数", and "易犯错的点". Use code blocks for examples and maintain a consistent tone.

10. **Review and Refinement:**  Read through the entire answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have just said "handles emphasis," but a better explanation would be to mention the stack-based approach in the `emph` function.

This structured approach helps in systematically dissecting the code, understanding its purpose, and addressing all aspects of the request. The key is to start with a high-level overview and then progressively dive into the details of the code's logic.
这段代码是 Go 语言 `rsc.io/markdown` 库中用于解析 Markdown **行内元素** 的部分。它的主要功能是将 Markdown 文本中的各种内联标记（例如 `*emphasis*`，`**strong**`，`[link](url)`，`![image](url)`，``code`` 等）解析成结构化的数据，以便后续渲染成 HTML 或其他格式。

**功能列表:**

1. **解析纯文本 (Plain Text):** 将不包含任何特殊 Markdown 标记的文本视为纯文本节点。
2. **解析强调 (Emphasis):**  识别 `*` 和 `_` 包围的文本，并根据 `*` 或 `_` 的数量确定是斜体 (`<em>`) 还是粗体 (`<strong>`)。 它还处理嵌套的强调。
3. **解析删除线 (Strikethrough):** 识别 `~~` 包围的文本，并将其标记为删除线 (`<del>`).
4. **解析代码 (Code):** 识别用反引号 `` ` `` 包围的文本，并将其标记为代码 (`<code>`). 它会处理代码中包含反引号的情况，选择合适数量的反引号作为分隔符。
5. **解析链接 (Links):** 识别 `[链接文本](链接地址 "可选标题")` 和引用链接 `[链接文本][链接标签]`  等格式，并提取链接文本、链接地址和标题。
6. **解析图片 (Images):** 识别 `![图片描述](图片地址 "可选标题")` 和引用图片 `![图片描述][链接标签]` 等格式，并提取图片描述和地址。
7. **解析转义字符 (Escaped Characters):** 处理反斜杠 `\` 转义的特殊字符，例如 `\*` 将被解析为 `*`。
8. **解析自动链接 (Autolinks):**  识别 `<` 和 `>` 包围的 URL 或邮箱地址，并将其转换为链接。
9. **解析 HTML 标签 (HTML Tags):** 允许在 Markdown 中嵌入部分 HTML 标签。
10. **解析 HTML 实体 (HTML Entities):**  将 HTML 实体（例如 `&amp;`）转换为相应的字符。
11. **解析硬换行 (Hard Breaks):**  识别以反斜杠加换行符 `\` 结尾的行，并将其转换为 `<br>` 标签。
12. **解析省略号 (Ellipsis):** 将 `...` 转换为 `…`。
13. **解析连接号 (Dashes):**  将连续的 `--`, `---`, `----` 等转换为 en 破折号 (`–`) 或 em 破折号 (`—`)。
14. **解析智能引号 (Smart Quotes):**  根据上下文将单引号和双引号转换为弯引号（例如 `‘`、`’`、`“`、`”`）。
15. **解析 Emoji (Emojis):**  识别 `:emoji_name:` 格式的 Emoji，并将其替换为 Unicode 字符。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 Markdown 语法中 **行内元素** 的解析逻辑。它利用 Go 语言的以下特性：

* **接口 (Interfaces):**  `Inline` 接口定义了所有行内元素都需要实现的方法，实现了多态。
* **结构体 (Structs):**  不同的行内元素（如 `Plain`，`Code`，`Strong` 等）用不同的结构体表示，用于存储解析后的数据。
* **方法 (Methods):**  结构体关联的方法（如 `PrintHTML`，`PrintText`，`printMarkdown`)  定义了如何将不同类型的行内元素渲染成不同的格式。
* **字符串操作 (String Manipulation):**  使用 `strings` 包中的函数进行字符串查找、分割、替换等操作，以识别 Markdown 标记。
* **Unicode 支持 (Unicode Support):**  使用 `unicode` 和 `unicode/utf8` 包来正确处理 Unicode 字符，例如在判断空格、标点符号时。
* **状态机 (Implicit State Machine):**  `parseState` 结构体以及 `inline` 函数中的循环和条件判断，隐式地实现了一个状态机，用于跟踪解析过程中的状态和上下文。

**Go 代码举例说明:**

假设有以下 Markdown 字符串作为输入：

```markdown
This is *italic* and **bold**. Here is some `code`. [A link](https://example.com). ![An image](image.png)
```

以下 Go 代码展示了如何使用这段代码（假设在一个名为 `markdown` 的包中）来解析这个字符串：

```go
package main

import (
	"bytes"
	"fmt"
	"go/src/cmd/vendor/rsc.io/markdown" // 假设你的代码在这个路径下
)

func main() {
	input := "This is *italic* and **bold**. Here is some `code`. [A link](https://example.com). ![An image](image.png)"
	ps := &markdown.parseState{} // 创建解析状态
	inlineElements := ps.inline(input)

	// 遍历解析后的行内元素并打印 HTML
	var buf bytes.Buffer
	for _, el := range inlineElements {
		el.PrintHTML(&buf)
	}
	fmt.Println(buf.String())
}
```

**假设的输出:**

```html
This is <em>italic</em> and <strong>bold</strong>. Here is some <code>code</code>. <a href="https://example.com">A link</a>. <img src="image.png" alt="An image">
```

**代码推理:**

* `ps := &markdown.parseState{}`:  创建了一个 `parseState` 实例，用于存储解析过程中的状态。
* `inlineElements := ps.inline(input)`: 调用 `inline` 方法对输入的 Markdown 字符串进行解析，返回一个 `Inline` 接口类型的切片。
* 循环遍历 `inlineElements`，并调用每个元素的 `PrintHTML` 方法将其渲染成 HTML。

**命令行参数的具体处理:**

这段代码本身 **不涉及** 命令行参数的具体处理。它是一个纯粹的 Markdown 行内元素解析器，不依赖于任何外部输入（除了要解析的字符串）。更上层的代码（例如处理 Markdown 文件的程序）可能会使用命令行参数来指定输入文件、输出格式等，但这部分代码只关注行内元素的解析。

**使用者易犯错的点:**

1. **强调标记不匹配或嵌套错误:**

   * **错误示例:** `*italic and bold**` (星号不匹配)
   * **错误示例:** `***bold and italic***` (三组星号可能被解析为嵌套，具体行为取决于解析器的实现细节，但很容易引起混淆)
   * **正确示例:** `*italic* and **bold**`

2. **链接或图片语法错误:**

   * **错误示例:** `[link without closing parenthesis`
   * **错误示例:** `[link](invalid url)`
   * **错误示例:** `![image without alt text](image.png)` （虽然 Markdown 允许没有 alt text，但某些解析器或渲染器可能会有警告）

3. **代码块反引号数量不匹配:**

   * **错误示例:** `` `code`` `` (代码块开始和结束的反引号数量不一致)
   * **正确示例:** `` `code` ``

4. **转义字符使用不当:**

   * **错误示例:** `\`后跟非特殊字符，例如 `\a`  (这通常会被当作普通的反斜杠和字符 'a')
   * **正确示例:** `\*` (转义星号，使其不被解析为强调标记)

5. **对智能引号的理解偏差:**  智能引号的转换依赖于上下文，有时可能不会如预期工作。 例如，在表示英尺或英寸时，单引号可能不希望被转换为弯引号。

**总结:**

这段 `inline.go` 文件是 `rsc.io/markdown` 库中负责解析 Markdown 行内语法的核心部分。它通过定义 `Inline` 接口和各种实现了该接口的结构体，将 Markdown 文本结构化表示，并提供了将其渲染成不同格式的能力。理解其功能和潜在的错误点，有助于更好地使用和调试 Markdown 解析器。

### 提示词
```
这是路径为go/src/cmd/vendor/rsc.io/markdown/inline.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package markdown

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

/*
text node can be

 - other literal text
 - run of * or _ characters
 - [
 - ![

keep delimiter stack pointing at non-other literal text
each node contains

 - type of delimiter [ ![ _ *
 - number of delimiters
 - active or not
 - potential opener, potential closer, or obth

when a ] is hit, call look for link or image
when end is hit, call process emphasis

look for link or image:

	find topmost [ or ![
	if none, emit literal ]
	if its inactive, remove and emit literal ]
	parse ahead to look for rest of link; if none, remove and emit literal ]
	run process emphasis on the interior,
	remove opener
	if this was a link (not an image), set all [ before opener to inactive, to avoid links inside links

process emphasis

	walk forward in list to find a closer.
	walk back to find first potential matching opener.
	if found:
		strong for length >= 2
		insert node
		drop delimiters between opener and closer
		remove 1 or 2 from open/close count, removing if now empty
		if closing has some left, go around again on this node
	if not:
		set openers bottom for this kind of element to before current_position
		if the closer at current pos is not an opener, remove it

seems needlessly complex. two passes

scan and find ` ` first.

pass 1. scan and find [ and ]() and leave the rest alone.

each completed one invokes emphasis on inner text and then on the overall list.

*/

type Inline interface {
	PrintHTML(*bytes.Buffer)
	PrintText(*bytes.Buffer)
	printMarkdown(*bytes.Buffer)
}

type Plain struct {
	Text string
}

func (*Plain) Inline() {}

func (x *Plain) PrintHTML(buf *bytes.Buffer) {
	htmlEscaper.WriteString(buf, x.Text)
}

func (x *Plain) printMarkdown(buf *bytes.Buffer) {
	buf.WriteString(x.Text)
}

func (x *Plain) PrintText(buf *bytes.Buffer) {
	htmlEscaper.WriteString(buf, x.Text)
}

type openPlain struct {
	Plain
	i int // position in input where bracket is
}

type emphPlain struct {
	Plain
	canOpen  bool
	canClose bool
	i        int // position in output where emph is
	n        int // length of original span
}

type Escaped struct {
	Plain
}

func (x *Escaped) printMarkdown(buf *bytes.Buffer) {
	buf.WriteByte('\\')
	x.Plain.printMarkdown(buf)
}

type Code struct {
	Text string
}

func (*Code) Inline() {}

func (x *Code) PrintHTML(buf *bytes.Buffer) {
	fmt.Fprintf(buf, "<code>%s</code>", htmlEscaper.Replace(x.Text))
}

func (x *Code) printMarkdown(buf *bytes.Buffer) {
	if len(x.Text) == 0 {
		return
	}
	// Use the fewest backticks we can, and add spaces as needed.
	ticks := strings.Repeat("`", longestSequence(x.Text, '`')+1)
	buf.WriteString(ticks)
	if x.Text[0] == '`' {
		buf.WriteByte(' ')
	}
	buf.WriteString(x.Text)
	if x.Text[len(x.Text)-1] == '`' {
		buf.WriteByte(' ')
	}
	buf.WriteString(ticks)
}

// longestSequence returns the length of the longest sequence of consecutive bytes b in s.
func longestSequence(s string, b byte) int {
	max := 0
	cur := 0
	for i := range s {
		if s[i] == b {
			cur++
		} else {
			if cur > max {
				max = cur
			}
			cur = 0
		}
	}
	if cur > max {
		max = cur
	}
	return max
}

func (x *Code) PrintText(buf *bytes.Buffer) {
	htmlEscaper.WriteString(buf, x.Text)
}

type Strong struct {
	Marker string
	Inner  []Inline
}

func (x *Strong) Inline() {
}

func (x *Strong) PrintHTML(buf *bytes.Buffer) {
	buf.WriteString("<strong>")
	for _, c := range x.Inner {
		c.PrintHTML(buf)
	}
	buf.WriteString("</strong>")
}

func (x *Strong) printMarkdown(buf *bytes.Buffer) {
	buf.WriteString(x.Marker)
	for _, c := range x.Inner {
		c.printMarkdown(buf)
	}
	buf.WriteString(x.Marker)
}

func (x *Strong) PrintText(buf *bytes.Buffer) {
	for _, c := range x.Inner {
		c.PrintText(buf)
	}
}

type Del struct {
	Marker string
	Inner  []Inline
}

func (x *Del) Inline() {

}

func (x *Del) PrintHTML(buf *bytes.Buffer) {
	buf.WriteString("<del>")
	for _, c := range x.Inner {
		c.PrintHTML(buf)
	}
	buf.WriteString("</del>")
}

func (x *Del) printMarkdown(buf *bytes.Buffer) {
	buf.WriteString(x.Marker)
	for _, c := range x.Inner {
		c.printMarkdown(buf)
	}
	buf.WriteString(x.Marker)
}

func (x *Del) PrintText(buf *bytes.Buffer) {
	for _, c := range x.Inner {
		c.PrintText(buf)
	}
}

type Emph struct {
	Marker string
	Inner  []Inline
}

func (*Emph) Inline() {}

func (x *Emph) PrintHTML(buf *bytes.Buffer) {
	buf.WriteString("<em>")
	for _, c := range x.Inner {
		c.PrintHTML(buf)
	}
	buf.WriteString("</em>")
}

func (x *Emph) printMarkdown(buf *bytes.Buffer) {
	buf.WriteString(x.Marker)
	for _, c := range x.Inner {
		c.printMarkdown(buf)
	}
	buf.WriteString(x.Marker)
}

func (x *Emph) PrintText(buf *bytes.Buffer) {
	for _, c := range x.Inner {
		c.PrintText(buf)
	}
}

func (p *parseState) emit(i int) {
	if p.emitted < i {
		p.list = append(p.list, &Plain{p.s[p.emitted:i]})
		p.emitted = i
	}
}

func (p *parseState) skip(i int) {
	p.emitted = i
}

func (p *parseState) inline(s string) []Inline {
	s = trimSpaceTab(s)
	// Scan text looking for inlines.
	// Leaf inlines are converted immediately.
	// Non-leaf inlines have potential starts pushed on a stack while we await completion.
	// Links take priority over other emphasis, so the emphasis must be delayed.
	p.s = s
	p.list = nil
	p.emitted = 0
	var opens []int // indexes of open ![ and [ Plains in p.list
	var lastLinkOpen int
	backticks := false
	i := 0
	for i < len(s) {
		var parser func(*parseState, string, int) (Inline, int, int, bool)
		switch s[i] {
		case '\\':
			parser = parseEscape
		case '`':
			if !backticks {
				backticks = true
				p.backticks.reset()
			}
			parser = p.backticks.parseCodeSpan
		case '<':
			parser = parseAutoLinkOrHTML
		case '[':
			parser = parseLinkOpen
		case '!':
			parser = parseImageOpen
		case '_', '*':
			parser = parseEmph
		case '.':
			if p.SmartDot {
				parser = parseDot
			}
		case '-':
			if p.SmartDash {
				parser = parseDash
			}
		case '"', '\'':
			if p.SmartQuote {
				parser = parseEmph
			}
		case '~':
			if p.Strikethrough {
				parser = parseEmph
			}
		case '\n': // TODO what about eof
			parser = parseBreak
		case '&':
			parser = parseHTMLEntity
		case ':':
			if p.Emoji {
				parser = parseEmoji
			}
		}
		if parser != nil {
			if x, start, end, ok := parser(p, s, i); ok {
				p.emit(start)
				if _, ok := x.(*openPlain); ok {
					opens = append(opens, len(p.list))
				}
				p.list = append(p.list, x)
				i = end
				p.skip(i)
				continue
			}
		}
		if s[i] == ']' && len(opens) > 0 {
			oi := opens[len(opens)-1]
			open := p.list[oi].(*openPlain)
			opens = opens[:len(opens)-1]
			if open.Text[0] == '!' || lastLinkOpen <= open.i {
				if x, end, ok := p.parseLinkClose(s, i, open); ok {
					p.corner = p.corner || x.corner || linkCorner(x.URL)
					p.emit(i)
					x.Inner = p.emph(nil, p.list[oi+1:])
					if open.Text[0] == '!' {
						p.list[oi] = (*Image)(x)
					} else {
						p.list[oi] = x
					}
					p.list = p.list[:oi+1]
					p.skip(end)
					i = end
					if open.Text[0] == '[' {
						// No links around links.
						lastLinkOpen = open.i
					}
					continue
				}
			}
		}
		i++
	}
	p.emit(len(s))
	p.list = p.emph(p.list[:0], p.list)
	p.list = p.mergePlain(p.list)
	p.list = p.autoLinkText(p.list)

	return p.list
}

func (ps *parseState) emph(dst, src []Inline) []Inline {
	const chars = "_*~\"'"
	var stack [len(chars)][]*emphPlain
	stackOf := func(c byte) int {
		return strings.IndexByte(chars, c)
	}

	trimStack := func() {
		for i := range stack {
			stk := &stack[i]
			for len(*stk) > 0 && (*stk)[len(*stk)-1].i >= len(dst) {
				*stk = (*stk)[:len(*stk)-1]
			}
		}
	}

Src:
	for i := 0; i < len(src); i++ {
		if open, ok := src[i].(*openPlain); ok {
			// Convert unused link/image open marker to plain text.
			dst = append(dst, &open.Plain)
			continue
		}
		p, ok := src[i].(*emphPlain)
		if !ok {
			dst = append(dst, src[i])
			continue
		}
		if p.canClose {
			stk := &stack[stackOf(p.Text[0])]
		Loop:
			for p.Text != "" {
				// Looking for same symbol and compatible with p.Text.
				for i := len(*stk) - 1; i >= 0; i-- {
					start := (*stk)[i]
					if (p.Text[0] == '*' || p.Text[0] == '_') && (p.canOpen && p.canClose || start.canOpen && start.canClose) && (p.n+start.n)%3 == 0 && (p.n%3 != 0 || start.n%3 != 0) {
						continue
					}
					if p.Text[0] == '~' && len(p.Text) != len(start.Text) { // ~ matches ~, ~~ matches ~~
						continue
					}
					if p.Text[0] == '"' {
						dst[start.i].(*emphPlain).Text = "“"
						p.Text = "”"
						dst = append(dst, p)
						*stk = (*stk)[:i]
						// no trimStack
						continue Src
					}
					if p.Text[0] == '\'' {
						dst[start.i].(*emphPlain).Text = "‘"
						p.Text = "’"
						dst = append(dst, p)
						*stk = (*stk)[:i]
						// no trimStack
						continue Src
					}
					var d int
					if len(p.Text) >= 2 && len(start.Text) >= 2 {
						// strong
						d = 2
					} else {
						// emph
						d = 1
					}
					del := p.Text[0] == '~'
					x := &Emph{Marker: p.Text[:d], Inner: append([]Inline(nil), dst[start.i+1:]...)}
					start.Text = start.Text[:len(start.Text)-d]
					p.Text = p.Text[d:]
					if start.Text == "" {
						dst = dst[:start.i]
					} else {
						dst = dst[:start.i+1]
					}
					trimStack()
					if del {
						dst = append(dst, (*Del)(x))
					} else if d == 2 {
						dst = append(dst, (*Strong)(x))
					} else {
						dst = append(dst, x)
					}
					continue Loop
				}
				break
			}
		}
		if p.Text != "" {
			stk := &stack[stackOf(p.Text[0])]
			if p.Text == "'" {
				p.Text = "’"
			}
			if p.Text == "\"" {
				if p.canClose {
					p.Text = "”"
				} else {
					p.Text = "“"
				}
			}
			if p.canOpen {
				p.i = len(dst)
				dst = append(dst, p)
				*stk = append(*stk, p)
			} else {
				dst = append(dst, &p.Plain)
			}
		}
	}
	return dst
}

func mdUnescape(s string) string {
	if !strings.Contains(s, `\`) && !strings.Contains(s, `&`) {
		return s
	}
	return mdUnescaper.Replace(s)
}

var mdUnescaper = func() *strings.Replacer {
	var list = []string{
		`\!`, `!`,
		`\"`, `"`,
		`\#`, `#`,
		`\$`, `$`,
		`\%`, `%`,
		`\&`, `&`,
		`\'`, `'`,
		`\(`, `(`,
		`\)`, `)`,
		`\*`, `*`,
		`\+`, `+`,
		`\,`, `,`,
		`\-`, `-`,
		`\.`, `.`,
		`\/`, `/`,
		`\:`, `:`,
		`\;`, `;`,
		`\<`, `<`,
		`\=`, `=`,
		`\>`, `>`,
		`\?`, `?`,
		`\@`, `@`,
		`\[`, `[`,
		`\\`, `\`,
		`\]`, `]`,
		`\^`, `^`,
		`\_`, `_`,
		"\\`", "`",
		`\{`, `{`,
		`\|`, `|`,
		`\}`, `}`,
		`\~`, `~`,
	}

	for name, repl := range htmlEntity {
		list = append(list, name, repl)
	}
	return strings.NewReplacer(list...)
}()

func isPunct(c byte) bool {
	return '!' <= c && c <= '/' || ':' <= c && c <= '@' || '[' <= c && c <= '`' || '{' <= c && c <= '~'
}

func parseEscape(p *parseState, s string, i int) (Inline, int, int, bool) {
	if i+1 < len(s) {
		c := s[i+1]
		if isPunct(c) {
			return &Escaped{Plain{s[i+1 : i+2]}}, i, i + 2, true
		}
		if c == '\n' { // TODO what about eof
			if i > 0 && s[i-1] == '\\' {
				p.corner = true // goldmark mishandles \\\ newline
			}
			end := i + 2
			for end < len(s) && (s[end] == ' ' || s[end] == '\t') {
				end++
			}
			return &HardBreak{}, i, end, true
		}
	}
	return nil, 0, 0, false
}

func parseDot(p *parseState, s string, i int) (Inline, int, int, bool) {
	if i+2 < len(s) && s[i+1] == '.' && s[i+2] == '.' {
		return &Plain{"…"}, i, i + 3, true
	}
	return nil, 0, 0, false
}

func parseDash(p *parseState, s string, i int) (Inline, int, int, bool) {
	if i+1 >= len(s) || s[i+1] != '-' {
		return nil, 0, 0, false
	}

	n := 2
	for i+n < len(s) && s[i+n] == '-' {
		n++
	}

	// Mimic cmark-gfm. Can't make this stuff up.
	em, en := 0, 0
	switch {
	case n%3 == 0:
		em = n / 3
	case n%2 == 0:
		en = n / 2
	case n%3 == 2:
		em = (n - 2) / 3
		en = 1
	case n%3 == 1:
		em = (n - 4) / 3
		en = 2
	}
	return &Plain{strings.Repeat("—", em) + strings.Repeat("–", en)}, i, i + n, true
}

// Inline code span markers must fit on punched cards, to match cmark-gfm.
const maxBackticks = 80

type backtickParser struct {
	last    [maxBackticks]int
	scanned bool
}

func (b *backtickParser) reset() {
	*b = backtickParser{}
}

func (b *backtickParser) parseCodeSpan(p *parseState, s string, i int) (Inline, int, int, bool) {
	start := i
	// Count leading backticks. Need to find that many again.
	n := 1
	for i+n < len(s) && s[i+n] == '`' {
		n++
	}

	// If we've already scanned the whole string (for a different count),
	// we can skip a failed scan by checking whether we saw this count.
	// To enable this optimization, following cmark-gfm, we declare by fiat
	// that more than maxBackticks backquotes is too many.
	if n > len(b.last) || b.scanned && b.last[n-1] < i+n {
		goto NoMatch
	}

	for end := i + n; end < len(s); {
		if s[end] != '`' {
			end++
			continue
		}
		estart := end
		for end < len(s) && s[end] == '`' {
			end++
		}
		m := end - estart
		if !b.scanned && m < len(b.last) {
			b.last[m-1] = estart
		}
		if m == n {
			// Match.
			// Line endings are converted to single spaces.
			text := s[i+n : estart]
			text = strings.ReplaceAll(text, "\n", " ")

			// If enclosed text starts and ends with a space and is not all spaces,
			// one space is removed from start and end, to allow `` ` `` to quote a single backquote.
			if len(text) >= 2 && text[0] == ' ' && text[len(text)-1] == ' ' && trimSpace(text) != "" {
				text = text[1 : len(text)-1]
			}

			return &Code{text}, start, end, true
		}
	}
	b.scanned = true

NoMatch:
	// No match, so none of these backticks count: skip them all.
	// For example ``x` is not a single backtick followed by a code span.
	// Returning nil, 0, false would advance to the second backtick and try again.
	return &Plain{s[i : i+n]}, start, i + n, true
}

func parseAutoLinkOrHTML(p *parseState, s string, i int) (Inline, int, int, bool) {
	if x, end, ok := parseAutoLinkURI(s, i); ok {
		return x, i, end, true
	}
	if x, end, ok := parseAutoLinkEmail(s, i); ok {
		return x, i, end, true
	}
	if x, end, ok := parseHTMLTag(p, s, i); ok {
		return x, i, end, true
	}
	return nil, 0, 0, false
}

func isLetter(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z'
}

func isLDH(c byte) bool {
	return isLetterDigit(c) || c == '-'
}

func isLetterDigit(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9'
}

func parseLinkOpen(_ *parseState, s string, i int) (Inline, int, int, bool) {
	return &openPlain{Plain{s[i : i+1]}, i + 1}, i, i + 1, true
}

func parseImageOpen(_ *parseState, s string, i int) (Inline, int, int, bool) {
	if i+1 < len(s) && s[i+1] == '[' {
		return &openPlain{Plain{s[i : i+2]}, i + 2}, i, i + 2, true
	}
	return nil, 0, 0, false
}

func parseEmph(p *parseState, s string, i int) (Inline, int, int, bool) {
	c := s[i]
	j := i + 1
	if c == '*' || c == '~' || c == '_' {
		for j < len(s) && s[j] == c {
			j++
		}
	}
	if c == '~' && j-i != 2 {
		// Goldmark does not accept ~text~
		// and incorrectly accepts ~~~text~~~.
		// Only ~~ is correct.
		p.corner = true
	}
	if c == '~' && j-i > 2 {
		return &Plain{s[i:j]}, i, j, true
	}

	var before, after rune
	if i == 0 {
		before = ' '
	} else {
		before, _ = utf8.DecodeLastRuneInString(s[:i])
	}
	if j >= len(s) {
		after = ' '
	} else {
		after, _ = utf8.DecodeRuneInString(s[j:])
	}

	// “A left-flanking delimiter run is a delimiter run that is
	// (1) not followed by Unicode whitespace, and either
	// (2a) not followed by a Unicode punctuation character, or
	// (2b) followed by a Unicode punctuation character
	// and preceded by Unicode whitespace or a Unicode punctuation character.
	// For purposes of this definition, the beginning and the end
	// of the line count as Unicode whitespace.”
	leftFlank := !isUnicodeSpace(after) &&
		(!isUnicodePunct(after) || isUnicodeSpace(before) || isUnicodePunct(before))

	// “A right-flanking delimiter run is a delimiter run that is
	// (1) not preceded by Unicode whitespace, and either
	// (2a) not preceded by a Unicode punctuation character, or
	// (2b) preceded by a Unicode punctuation character
	// and followed by Unicode whitespace or a Unicode punctuation character.
	// For purposes of this definition, the beginning and the end
	// of the line count as Unicode whitespace.”
	rightFlank := !isUnicodeSpace(before) &&
		(!isUnicodePunct(before) || isUnicodeSpace(after) || isUnicodePunct(after))

	var canOpen, canClose bool

	switch c {
	case '\'', '"':
		canOpen = leftFlank && !rightFlank && before != ']' && before != ')'
		canClose = rightFlank
	case '*', '~':
		// “A single * character can open emphasis iff
		// it is part of a left-flanking delimiter run.”

		// “A double ** can open strong emphasis iff
		// it is part of a left-flanking delimiter run.”
		canOpen = leftFlank

		// “A single * character can close emphasis iff
		// it is part of a right-flanking delimiter run.”

		// “A double ** can close strong emphasis iff
		// it is part of a right-flanking delimiter run.”
		canClose = rightFlank
	case '_':
		// “A single _ character can open emphasis iff
		// it is part of a left-flanking delimiter run and either
		// (a) not part of a right-flanking delimiter run or
		// (b) part of a right-flanking delimiter run preceded by a Unicode punctuation character.”

		// “A double __ can open strong emphasis iff
		// it is part of a left-flanking delimiter run and either
		// (a) not part of a right-flanking delimiter run or
		// (b) part of a right-flanking delimiter run preceded by a Unicode punctuation character.”
		canOpen = leftFlank && (!rightFlank || isUnicodePunct(before))

		// “A single _ character can close emphasis iff
		// it is part of a right-flanking delimiter run and either
		// (a) not part of a left-flanking delimiter run or
		// (b) part of a left-flanking delimiter run followed by a Unicode punctuation character.”

		// “A double __ can close strong emphasis iff
		// it is part of a right-flanking delimiter run and either
		// (a) not part of a left-flanking delimiter run or
		// (b) part of a left-flanking delimiter run followed by a Unicode punctuation character.”
		canClose = rightFlank && (!leftFlank || isUnicodePunct(after))
	}

	return &emphPlain{Plain: Plain{s[i:j]}, canOpen: canOpen, canClose: canClose, n: j - i}, i, j, true
}

func isUnicodeSpace(r rune) bool {
	if r < 0x80 {
		return r == ' ' || r == '\t' || r == '\f' || r == '\n'
	}
	return unicode.In(r, unicode.Zs)
}

func isUnicodePunct(r rune) bool {
	if r < 0x80 {
		return isPunct(byte(r))
	}
	return unicode.In(r, unicode.Punct)
}

func (p *parseState) parseLinkClose(s string, i int, open *openPlain) (*Link, int, bool) {
	if i+1 < len(s) {
		switch s[i+1] {
		case '(':
			// Inline link - [Text](Dest Title), with Title omitted or both Dest and Title omitted.
			i := skipSpace(s, i+2)
			var dest, title string
			var titleChar byte
			var corner bool
			if i < len(s) && s[i] != ')' {
				var ok bool
				dest, i, ok = parseLinkDest(s, i)
				if !ok {
					break
				}
				i = skipSpace(s, i)
				if i < len(s) && s[i] != ')' {
					title, titleChar, i, ok = parseLinkTitle(s, i)
					if title == "" {
						corner = true
					}
					if !ok {
						break
					}
					i = skipSpace(s, i)
				}
			}
			if i < len(s) && s[i] == ')' {
				return &Link{URL: dest, Title: title, TitleChar: titleChar, corner: corner}, i + 1, true
			}
			// NOTE: Test malformed ( ) with shortcut reference
			// TODO fall back on syntax error?

		case '[':
			// Full reference link - [Text][Label]
			label, i, ok := parseLinkLabel(p, s, i+1)
			if !ok {
				break
			}
			if link, ok := p.links[normalizeLabel(label)]; ok {
				return &Link{URL: link.URL, Title: link.Title, corner: link.corner}, i, true
			}
			// Note: Could break here, but CommonMark dingus does not
			// fall back to trying Text for [Text][Label] when Label is unknown.
			// Unclear from spec what the correct answer is.
			return nil, 0, false
		}
	}

	// Collapsed or shortcut reference link: [Text][] or [Text].
	end := i + 1
	if strings.HasPrefix(s[end:], "[]") {
		end += 2
	}

	if link, ok := p.links[normalizeLabel(s[open.i:i])]; ok {
		return &Link{URL: link.URL, Title: link.Title, corner: link.corner}, end, true
	}
	return nil, 0, false
}

func skipSpace(s string, i int) int {
	// Note: Blank lines have already been removed.
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
		i++
	}
	return i
}

func linkCorner(url string) bool {
	for i := 0; i < len(url); i++ {
		if url[i] == '%' {
			if i+2 >= len(url) || !isHexDigit(url[i+1]) || !isHexDigit(url[i+2]) {
				// Goldmark and the Dingus re-escape such percents as %25,
				// but the spec does not seem to require this behavior.
				return true
			}
		}
	}
	return false
}

func (p *parseState) mergePlain(list []Inline) []Inline {
	out := list[:0]
	start := 0
	for i := 0; ; i++ {
		if i < len(list) && toPlain(list[i]) != nil {
			continue
		}
		// Non-Plain or end of list.
		if start < i {
			out = append(out, mergePlain1(list[start:i]))
		}
		if i >= len(list) {
			break
		}
		out = append(out, list[i])
		start = i + 1
	}
	return out
}

func toPlain(x Inline) *Plain {
	// TODO what about Escaped?
	switch x := x.(type) {
	case *Plain:
		return x
	case *emphPlain:
		return &x.Plain
	case *openPlain:
		return &x.Plain
	}
	return nil
}

func mergePlain1(list []Inline) *Plain {
	if len(list) == 1 {
		return toPlain(list[0])
	}
	var all []string
	for _, pl := range list {
		all = append(all, toPlain(pl).Text)
	}
	return &Plain{Text: strings.Join(all, "")}
}

func parseEmoji(p *parseState, s string, i int) (Inline, int, int, bool) {
	for j := i + 1; ; j++ {
		if j >= len(s) || j-i > 2+maxEmojiLen {
			break
		}
		if s[j] == ':' {
			name := s[i+1 : j]
			if utf, ok := emoji[name]; ok {
				return &Emoji{s[i : j+1], utf}, i, j + 1, true
			}
			break
		}
	}
	return nil, 0, 0, false
}

type Emoji struct {
	Name string // emoji :name:, including colons
	Text string // Unicode for emoji sequence
}

func (*Emoji) Inline() {}

func (x *Emoji) PrintHTML(buf *bytes.Buffer) {
	htmlEscaper.WriteString(buf, x.Text)
}

func (x *Emoji) printMarkdown(buf *bytes.Buffer) {
	buf.WriteString(x.Text)
}

func (x *Emoji) PrintText(buf *bytes.Buffer) {
	htmlEscaper.WriteString(buf, x.Text)
}
```