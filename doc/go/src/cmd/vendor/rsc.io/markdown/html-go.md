Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Functionality:** The file name `html.go` within a `markdown` package strongly suggests this code is responsible for handling HTML within Markdown. Specifically, it looks like it's about recognizing and processing HTML blocks and inline HTML tags.

2. **Examine the Data Structures:**
    * `HTMLBlock`: This struct clearly represents a block of HTML. It stores the raw HTML text as a slice of strings (`Text`) and its position in the document. The `PrintHTML` method confirms its purpose: to output the stored HTML.
    * `htmlBuilder`: This looks like a helper struct used during parsing. The `extend` method appending lines of text and the `build` method creating an `HTMLBlock` suggest it accumulates HTML lines until a complete block is identified. The `endFunc` suggests different conditions for ending an HTML block.

3. **Analyze Key Functions:**
    * `newHTML`:  This function seems to be the entry point for detecting HTML blocks. It calls `p.startHTML`.
    * `(*parseState).startHTML`: This is where the core logic for identifying different types of HTML constructs resides. It checks for various HTML prefixes (`<!--`, `<?`, `<![CDATA[`, `<!`) and uses different logic based on the detected prefix. It also handles "case 6" HTML tags (block-level tags) and "case 1" (tags like `pre`, `script`, etc.) which have specific ending tags. The "case 7" handles single open and closing tags in certain contexts.
    * `hasEndPre`: This function specifically checks if a string contains a closing tag for `pre`, `script`, `style`, or `textarea`.
    * `parseHTMLTag`, `parseHTMLOpenTag`, `parseHTMLClosingTag`, `parseTagName`, `parseAttr`, `parseAttrName`, `parseAttrValueSpec`, `parseAttrValue`, `parseHTMLComment`, `parseHTMLCDATA`, `parseHTMLDecl`, `parseHTMLProcInst`, `parseHTMLMarker`: These functions are clearly involved in parsing inline HTML tags and their attributes. They break down the HTML syntax into smaller components.
    * `parseHTMLEntity`: This handles HTML entities (like `&nbsp;` or `&#160;`).
    * `HTMLTag`: This struct represents an inline HTML tag.

4. **Infer Go Feature Implementation:** Based on the identified functionality, this code implements Markdown's ability to include raw HTML. This is a standard feature of Markdown that allows for embedding arbitrary HTML within a Markdown document.

5. **Develop Example Code:**  To illustrate how this code might be used, create a simple Markdown example containing HTML. Then, simulate the parsing process. Show how the `HTMLBlock` and `HTMLTag` structures would be populated. Crucially, demonstrate the output by calling the `PrintHTML` methods.

6. **Identify Command-Line Argument Handling (or Lack Thereof):**  Carefully scan the code for any interaction with `os.Args` or the `flag` package. In this snippet, there's no evidence of command-line argument processing. State this explicitly.

7. **Pinpoint Potential User Errors:** Think about common mistakes people make when embedding HTML in Markdown:
    * **Unclosed tags:** This is a classic HTML error. Show how the parser might handle (or not handle) this.
    * **Incorrect nesting:** Again, a common HTML issue.
    * **Mixing Markdown and HTML syntax in unexpected ways:**  For instance, trying to apply Markdown formatting *inside* an HTML tag's content might not work as expected. Provide a concrete example.

8. **Structure the Answer:** Organize the findings logically:
    * Start with a concise summary of the file's purpose.
    * Detail the functionalities based on the code analysis.
    * Provide the Go code example with clear input and output.
    * Explicitly address command-line arguments (or their absence).
    * Highlight potential user errors with illustrative examples.
    * Use clear and concise Chinese.

9. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, the `corner` variable is mentioned, and while a deep dive into its specific purpose might be beyond the scope of the initial request, acknowledging its presence and hinting at its role in handling minor spec deviations is helpful.

This step-by-step process, combining code examination, logical deduction, and practical examples, leads to a comprehensive understanding of the provided Go code and the generation of a helpful and informative answer.
这段Go语言代码是 `rsc.io/markdown` 库中负责处理 HTML 块和内联 HTML 标签的部分。它的主要功能是：

1. **识别和存储 HTML 块 (HTMLBlock):**  代码能够识别 Markdown 文档中的 HTML 块级元素，例如 `<script>`, `<style>`, `<iframe>` 等，并将这些块的内容原样存储起来。
2. **识别和存储内联 HTML 标签 (HTMLTag):**  代码也能够识别 Markdown 文档中的内联 HTML 标签，例如 `<a>`, `<span>`, `<img>` 等，并将这些标签原样存储起来。
3. **在 HTML 输出中保留原始 HTML:**  当将 Markdown 文档转换为 HTML 时，这段代码能够将识别出的 HTML 块和内联标签直接输出到 HTML 结果中，不做任何修改或转义。
4. **在 Markdown 输出中保留原始 HTML (部分情况):**  在将 Markdown 转换回 Markdown 的某些场景下，这段代码也负责将 HTML 块以原始形式输出。
5. **处理不同类型的 HTML 结构:**  代码能够处理多种 HTML 结构，包括：
    * HTML 注释 (`<!-- ... -->`)
    * 处理指令 (`<? ... ?>`)
    * CDATA 区块 (`<![CDATA[ ... ]]>`)
    * 声明 (`<!DOCTYPE ...>`)
    * 常规的 HTML 标签（包括自闭合标签）

**它是什么Go语言功能的实现？**

这段代码主要实现了 Markdown 语法规范中对于 HTML 内容的处理。Markdown 允许在文档中嵌入原始 HTML 代码，这段代码就是负责解析和保留这些 HTML 代码的。它涉及到字符串处理、状态管理（通过 `parseState` 和 `buildState`）、以及构建抽象语法树（通过 `Block` 和 `Inline` 接口）。

**Go代码举例说明:**

假设有以下 Markdown 输入：

```markdown
这是一个段落。

<div>
  这是一个 div 块。
  <p>这是 div 块内的段落。</p>
</div>

这是一行包含 <strong>内联 HTML</strong> 的文字。
```

经过 `rsc.io/markdown` 库的解析，`html.go` 中的代码会识别出：

* 一个 `HTMLBlock` 类型的块，包含：
  ```
  <div>
    这是一个 div 块。
    <p>这是 div 块内的段落。</p>
  </div>
  ```
* 一个 `HTMLTag` 类型的内联元素，包含 `<strong>内联 HTML</strong>`。

以下是如何使用这段代码（模拟解析过程）：

```go
package main

import (
	"bytes"
	"fmt"
	"strings"
)

// 模拟 HTMLBlock 结构
type HTMLBlock struct {
	Text []string
}

func (b *HTMLBlock) PrintHTML(buf *bytes.Buffer) {
	for _, s := range b.Text {
		buf.WriteString(s)
		buf.WriteString("\n")
	}
}

// 模拟 HTMLTag 结构
type HTMLTag struct {
	Text string
}

func (t *HTMLTag) PrintHTML(buf *bytes.Buffer) {
	buf.WriteString(t.Text)
}

func main() {
	markdownInput := `这是一个段落。

<div>
  这是一个 div 块。
  <p>这是 div 块内的段落。</p>
</div>

这是一行包含 <strong>内联 HTML</strong> 的文字。`

	lines := strings.Split(markdownInput, "\n")

	var blocks []interface{} // 存储解析后的块级元素

	// 模拟 HTML 块的识别
	inHTMLBlock := false
	currentHTMLBlock := &HTMLBlock{Text: []string{}}
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "<") && strings.HasSuffix(trimmedLine, ">") && !inHTMLBlock {
			inHTMLBlock = true
			currentHTMLBlock.Text = append(currentHTMLBlock.Text, line)
		} else if inHTMLBlock {
			currentHTMLBlock.Text = append(currentHTMLBlock.Text, line)
			if strings.HasPrefix(trimmedLine, "</") { // 简化的结束判断
				blocks = append(blocks, currentHTMLBlock)
				currentHTMLBlock = &HTMLBlock{Text: []string{}}
				inHTMLBlock = false
			}
		} else if trimmedLine != "" {
			// 这里简单假设非空行且非 HTML 块起始为普通段落
			blocks = append(blocks, "Paragraph: "+trimmedLine)
		}
	}

	// 模拟内联 HTML 的识别 (非常简化)
	inlineText := "这是一行包含 <strong>内联 HTML</strong> 的文字。"
	var inlineElements []interface{}
	if strings.Contains(inlineText, "<") && strings.Contains(inlineText, ">") {
		startIndex := strings.Index(inlineText, "<")
		endIndex := strings.LastIndex(inlineText, ">") + 1
		htmlTag := &HTMLTag{Text: inlineText[startIndex:endIndex]}
		inlineElements = append(inlineElements, htmlTag)
	}

	// 模拟 HTML 输出
	var htmlOutput bytes.Buffer
	for _, block := range blocks {
		switch b := block.(type) {
		case *HTMLBlock:
			b.PrintHTML(&htmlOutput)
		case string:
			htmlOutput.WriteString("<p>" + b[len("Paragraph: "):] + "</p>\n")
		}
	}
	for _, inline := range inlineElements {
		switch t := inline.(type) {
		case *HTMLTag:
			t.PrintHTML(&htmlOutput)
		}
	}

	fmt.Println(htmlOutput.String())
}
```

**假设的输入与输出:**

**输入 (模拟 Markdown 内容):**

```
<div>
  <p>这是一个 HTML 段落。</p>
</div>
```

**输出 (模拟 `PrintHTML` 方法的输出):**

```
<div>
  <p>这是一个 HTML 段落。</p>
</div>
```

**涉及命令行参数的具体处理:**

这段代码本身似乎不直接处理命令行参数。`rsc.io/markdown` 库作为一个库，其命令行参数的处理通常会在使用它的更上层应用中进行。例如，如果有一个将 Markdown 文件转换为 HTML 的命令行工具使用了这个库，那么处理输入文件路径、输出文件路径等参数的逻辑会在那个工具的代码中实现，而不是在这里。

**使用者易犯错的点:**

使用者在使用 Markdown 嵌入 HTML 时，容易犯以下错误：

1. **未闭合的 HTML 标签:**  Markdown 解析器通常会按照 HTML 的规则来解析 HTML 代码，因此未闭合的标签可能导致解析结果不符合预期。

   **例子:**

   ```markdown
   <div>
     <p>这是一个段落。
   </div>
   ```

   上面的例子中，`<p>` 标签没有闭合，不同的 Markdown 解析器可能有不同的处理方式，可能会导致后续的内容被错误地解析为 `<p>` 标签的内容。

2. **HTML 块的起始和结束规则不明确:**  Markdown 对 HTML 块的识别有一定的规则，例如，块级 HTML 标签必须独占一行，并且标签的前后不能有其他内容。不遵守这些规则可能导致 HTML 块无法被正确识别。

   **例子:**

   ```markdown
   这是一个段落。<div>这是一个 div 块。</div>
   ```

   在这个例子中，`<div>` 标签没有独占一行，很可能不会被解析为 HTML 块。

3. **在不应该使用 HTML 的地方使用了 HTML:**  虽然 Markdown 允许嵌入 HTML，但过度或不恰当地使用 HTML 会降低 Markdown 的可读性和跨平台性。例如，仅仅为了添加一些简单的样式就使用 `<span>` 标签可能不是最佳实践，应该优先使用 Markdown 的语法。

4. **HTML 转义问题:**  有时候使用者可能期望 Markdown 引擎会自动转义 HTML 代码中的特殊字符（例如 `<`, `>`），但对于 HTML 块和标签，通常是按原样输出的。如果需要显示 HTML 字符本身而不是作为标签，则需要使用 HTML 实体（例如 `&lt;`, `&gt;`）。

总而言之，`go/src/cmd/vendor/rsc.io/markdown/html.go` 这部分代码专注于 Markdown 中 HTML 内容的识别和存储，为后续的 HTML 或 Markdown 输出提供基础。它本身不涉及复杂的命令行参数处理，但其功能是 Markdown 解析器中至关重要的一部分。

Prompt: 
```
这是路径为go/src/cmd/vendor/rsc.io/markdown/html.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package markdown

import (
	"bytes"
	"strconv"
	"strings"
	"unicode"
)

type HTMLBlock struct {
	Position
	Text []string
}

func (b *HTMLBlock) PrintHTML(buf *bytes.Buffer) {
	for _, s := range b.Text {
		buf.WriteString(s)
		buf.WriteString("\n")
	}
}

func (b *HTMLBlock) printMarkdown(buf *bytes.Buffer, s mdState) {
	if s.prefix1 != "" {
		buf.WriteString(s.prefix1)
	} else {
		buf.WriteString(s.prefix)
	}
	b.PrintHTML(buf)
}

type htmlBuilder struct {
	endBlank bool
	text     []string
	endFunc  func(string) bool
}

func (c *htmlBuilder) extend(p *parseState, s line) (line, bool) {
	if c.endBlank && s.isBlank() {
		return s, false
	}
	t := s.string()
	c.text = append(c.text, t)
	if c.endFunc != nil && c.endFunc(t) {
		return line{}, false
	}
	return line{}, true
}

func (c *htmlBuilder) build(p buildState) Block {
	return &HTMLBlock{
		p.pos(),
		c.text,
	}
}

func newHTML(p *parseState, s line) (line, bool) {
	peek := s
	if p.startHTML(&peek) {
		return line{}, true
	}
	return s, false
}

func (p *parseState) startHTML(s *line) bool {
	tt := *s
	tt.trimSpace(0, 3, false)
	if tt.peek() != '<' {
		return false
	}
	t := tt.string()

	var end string
	switch {
	case strings.HasPrefix(t, "<!--"):
		end = "-->"
	case strings.HasPrefix(t, "<?"):
		end = "?>"
	case strings.HasPrefix(t, "<![CDATA["):
		end = "]]>"
	case strings.HasPrefix(t, "<!") && len(t) >= 3 && isLetter(t[2]):
		if 'a' <= t[2] && t[2] <= 'z' {
			// Goldmark and the Dingus only accept <!UPPER> not <!lower>.
			p.corner = true
		}
		end = ">"
	}
	if end != "" {
		b := &htmlBuilder{endFunc: func(s string) bool { return strings.Contains(s, end) }}
		p.addBlock(b)
		b.text = append(b.text, s.string())
		if b.endFunc(t) {
			p.closeBlock()
		}
		return true
	}

	// case 6
	i := 1
	if i < len(t) && t[i] == '/' {
		i++
	}
	buf := make([]byte, 0, 16)
	for ; i < len(t) && len(buf) < 16; i++ {
		c := t[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if !('a' <= c && c <= 'z') && !('0' <= c && c <= '9') {
			break
		}
		buf = append(buf, c)
	}
	var sep byte
	if i < len(t) {
		switch t[i] {
		default:
			goto Next
		case ' ', '\t', '>':
			// ok
			sep = t[i]
		case '/':
			if i+1 >= len(t) || t[i+1] != '>' {
				goto Next
			}
		}
	}

	if len(buf) == 0 {
		goto Next
	}
	{
		c := buf[0]
		var ok bool
		for _, name := range htmlTags {
			if name[0] == c && len(name) == len(buf) && name == string(buf) {
				if sep == '\t' {
					// Goldmark recognizes space here but not tab.
					// testdata/extra.txt 143.md
					p.corner = true
				}
				ok = true
				break
			}
		}
		if !ok {
			goto Next
		}
	}

	{
		b := &htmlBuilder{endBlank: true}
		p.addBlock(b)
		b.text = append(b.text, s.string())
		return true
	}

Next:
	// case 1
	if len(t) > 1 && t[1] != '/' && (i >= len(t) || t[i] == ' ' || t[i] == '\t' || t[i] == '>') {
		switch string(buf) {
		case "pre", "script", "style", "textarea":
			b := &htmlBuilder{endFunc: hasEndPre}
			p.addBlock(b)
			b.text = append(b.text, s.string())
			if hasEndPre(t) {
				p.closeBlock()
			}
			return true
		}
	}

	// case 7
	if p.para() == nil {
		if _, e, ok := parseHTMLOpenTag(p, t, 0); ok && skipSpace(t, e) == len(t) {
			if e != len(t) {
				// Goldmark disallows trailing space
				p.corner = true
			}
			b := &htmlBuilder{endBlank: true}
			p.addBlock(b)
			b.text = append(b.text, s.string())
			return true
		}
		if _, e, ok := parseHTMLClosingTag(p, t, 0); ok && skipSpace(t, e) == len(t) {
			b := &htmlBuilder{endBlank: true}
			p.addBlock(b)
			b.text = append(b.text, s.string())
			return true
		}
	}

	return false
}

func hasEndPre(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '<' && i+1 < len(s) && s[i+1] == '/' {
			buf := make([]byte, 0, 8)
			for i += 2; i < len(s) && len(buf) < 8; i++ {
				c := s[i]
				if 'A' <= c && c <= 'Z' {
					c += 'a' - 'A'
				}
				if c < 'a' || 'z' < c {
					break
				}
				buf = append(buf, c)
			}
			if i < len(s) && s[i] == '>' {
				switch string(buf) {
				case "pre", "script", "style", "textarea":
					return true
				}
			}
		}
	}
	return false
}

func parseHTMLTag(p *parseState, s string, i int) (Inline, int, bool) {
	// “An HTML tag consists of an open tag, a closing tag, an HTML comment,
	// a processing instruction, a declaration, or a CDATA section.”
	if i+3 <= len(s) && s[i] == '<' {
		switch s[i+1] {
		default:
			return parseHTMLOpenTag(p, s, i)
		case '/':
			return parseHTMLClosingTag(p, s, i)
		case '!':
			switch s[i+2] {
			case '-':
				return parseHTMLComment(s, i)
			case '[':
				return parseHTMLCDATA(s, i)
			default:
				return parseHTMLDecl(p, s, i)
			}
		case '?':
			return parseHTMLProcInst(s, i)
		}
	}
	return nil, 0, false
}

func parseHTMLOpenTag(p *parseState, s string, i int) (Inline, int, bool) {
	if i >= len(s) || s[i] != '<' {
		return nil, 0, false
	}
	// “An open tag consists of a < character, a tag name, zero or more attributes,
	// optional spaces, tabs, and up to one line ending, an optional / character, and a > character.”
	if name, j, ok := parseTagName(s, i+1); ok {
		switch name {
		case "pre", "script", "style", "textarea":
			// Goldmark treats these as starting a new HTMLBlock
			// and ending the paragraph they appear in.
			p.corner = true
		}
		for {
			if j >= len(s) || s[j] != ' ' && s[j] != '\t' && s[j] != '\n' && s[j] != '/' && s[j] != '>' {
				return nil, 0, false
			}
			_, k, ok := parseAttr(p, s, j)
			if !ok {
				break
			}
			j = k
		}
		k := skipSpace(s, j)
		if k != j {
			// Goldmark mishandles spaces before >.
			p.corner = true
		}
		j = k
		if j < len(s) && s[j] == '/' {
			j++
		}
		if j < len(s) && s[j] == '>' {
			return &HTMLTag{s[i : j+1]}, j + 1, true
		}
	}
	return nil, 0, false
}

func parseHTMLClosingTag(p *parseState, s string, i int) (Inline, int, bool) {
	// “A closing tag consists of the string </, a tag name,
	// optional spaces, tabs, and up to one line ending, and the character >.”
	if i+2 >= len(s) || s[i] != '<' || s[i+1] != '/' {
		return nil, 0, false
	}
	if skipSpace(s, i+2) != i+2 {
		// Goldmark allows spaces here but the spec and the Dingus do not.
		p.corner = true
	}

	if _, j, ok := parseTagName(s, i+2); ok {
		j = skipSpace(s, j)
		if j < len(s) && s[j] == '>' {
			return &HTMLTag{s[i : j+1]}, j + 1, true
		}
	}
	return nil, 0, false
}

func parseTagName(s string, i int) (string, int, bool) {
	// “A tag name consists of an ASCII letter followed by zero or more ASCII letters, digits, or hyphens (-).”
	if i < len(s) && isLetter(s[i]) {
		j := i + 1
		for j < len(s) && isLDH(s[j]) {
			j++
		}
		return s[i:j], j, true
	}
	return "", 0, false
}

func parseAttr(p *parseState, s string, i int) (string, int, bool) {
	// “An attribute consists of spaces, tabs, and up to one line ending,
	// an attribute name, and an optional attribute value specification.”
	i = skipSpace(s, i)
	if _, j, ok := parseAttrName(s, i); ok {
		if _, k, ok := parseAttrValueSpec(p, s, j); ok {
			j = k
		}
		return s[i:j], j, true
	}
	return "", 0, false
}

func parseAttrName(s string, i int) (string, int, bool) {
	// “An attribute name consists of an ASCII letter, _, or :,
	// followed by zero or more ASCII letters, digits, _, ., :, or -.”
	if i+1 < len(s) && (isLetter(s[i]) || s[i] == '_' || s[i] == ':') {
		j := i + 1
		for j < len(s) && (isLDH(s[j]) || s[j] == '_' || s[j] == '.' || s[j] == ':') {
			j++
		}
		return s[i:j], j, true
	}
	return "", 0, false
}

func parseAttrValueSpec(p *parseState, s string, i int) (string, int, bool) {
	// “An attribute value specification consists of
	// optional spaces, tabs, and up to one line ending,
	// a = character,
	// optional spaces, tabs, and up to one line ending,
	// and an attribute value.”
	i = skipSpace(s, i)
	if i+1 < len(s) && s[i] == '=' {
		i = skipSpace(s, i+1)
		if _, j, ok := parseAttrValue(s, i); ok {
			p.corner = p.corner || strings.Contains(s[i:j], "\ufffd")
			return s[i:j], j, true
		}
	}
	return "", 0, false
}

func parseAttrValue(s string, i int) (string, int, bool) {
	// “An attribute value consists of
	// an unquoted attribute value,
	// a single-quoted attribute value,
	// or a double-quoted attribute value.”
	// TODO: No escaping???
	if i < len(s) && (s[i] == '\'' || s[i] == '"') {
		// “A single-quoted attribute value consists of ',
		// zero or more characters not including ', and a final '.”
		// “A double-quoted attribute value consists of ",
		// zero or more characters not including ", and a final ".”
		if j := strings.IndexByte(s[i+1:], s[i]); j >= 0 {
			end := i + 1 + j + 1
			return s[i:end], end, true
		}
	}

	// “An unquoted attribute value is a nonempty string of characters
	// not including spaces, tabs, line endings, ", ', =, <, >, or `.”
	j := i
	for j < len(s) && strings.IndexByte(" \t\n\"'=<>`", s[j]) < 0 {
		j++
	}
	if j > i {
		return s[i:j], j, true
	}
	return "", 0, false
}

func parseHTMLComment(s string, i int) (Inline, int, bool) {
	// “An HTML comment consists of <!-- + text + -->,
	// where text does not start with > or ->,
	// does not end with -, and does not contain --.”
	if !strings.HasPrefix(s[i:], "<!-->") &&
		!strings.HasPrefix(s[i:], "<!--->") {
		if x, end, ok := parseHTMLMarker(s, i, "<!--", "-->"); ok {
			if t := x.(*HTMLTag).Text; !strings.Contains(t[len("<!--"):len(t)-len("->")], "--") {
				return x, end, ok
			}
		}
	}
	return nil, 0, false
}

func parseHTMLCDATA(s string, i int) (Inline, int, bool) {
	// “A CDATA section consists of the string <![CDATA[,
	// a string of characters not including the string ]]>, and the string ]]>.”
	return parseHTMLMarker(s, i, "<![CDATA[", "]]>")
}

func parseHTMLDecl(p *parseState, s string, i int) (Inline, int, bool) {
	// “A declaration consists of the string <!, an ASCII letter,
	// zero or more characters not including the character >, and the character >.”
	if i+2 < len(s) && isLetter(s[i+2]) {
		if 'a' <= s[i+2] && s[i+2] <= 'z' {
			p.corner = true // goldmark requires uppercase
		}
		return parseHTMLMarker(s, i, "<!", ">")
	}
	return nil, 0, false
}

func parseHTMLProcInst(s string, i int) (Inline, int, bool) {
	// “A processing instruction consists of the string <?,
	// a string of characters not including the string ?>, and the string ?>.”
	return parseHTMLMarker(s, i, "<?", "?>")
}

func parseHTMLMarker(s string, i int, prefix, suffix string) (Inline, int, bool) {
	if strings.HasPrefix(s[i:], prefix) {
		if j := strings.Index(s[i+len(prefix):], suffix); j >= 0 {
			end := i + len(prefix) + j + len(suffix)
			return &HTMLTag{s[i:end]}, end, true
		}
	}
	return nil, 0, false
}

func parseHTMLEntity(_ *parseState, s string, i int) (Inline, int, int, bool) {
	start := i
	if i+1 < len(s) && s[i+1] == '#' {
		i += 2
		var r, end int
		if i < len(s) && (s[i] == 'x' || s[i] == 'X') {
			// hex
			i++
			j := i
			for j < len(s) && isHexDigit(s[j]) {
				j++
			}
			if j-i < 1 || j-i > 6 || j >= len(s) || s[j] != ';' {
				return nil, 0, 0, false
			}
			r64, _ := strconv.ParseInt(s[i:j], 16, 0)
			r = int(r64)
			end = j + 1
		} else {
			// decimal
			j := i
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			if j-i < 1 || j-i > 7 || j >= len(s) || s[j] != ';' {
				return nil, 0, 0, false
			}
			r, _ = strconv.Atoi(s[i:j])
			end = j + 1
		}
		if r > unicode.MaxRune || r == 0 {
			r = unicode.ReplacementChar
		}
		return &Plain{string(rune(r))}, start, end, true
	}

	// Max name in list is 32 bytes. Try for 64 for good measure.
	for j := i + 1; j < len(s) && j-i < 64; j++ {
		if s[j] == '&' { // Stop possible quadratic search on &&&&&&&.
			break
		}
		if s[j] == ';' {
			if r, ok := htmlEntity[s[i:j+1]]; ok {
				return &Plain{r}, start, j + 1, true
			}
			break
		}
	}

	return nil, 0, 0, false
}

type HTMLTag struct {
	Text string
}

func (*HTMLTag) Inline() {}

func (x *HTMLTag) PrintHTML(buf *bytes.Buffer) {
	buf.WriteString(x.Text)
}

func (x *HTMLTag) printMarkdown(buf *bytes.Buffer) {
	x.PrintHTML(buf)
}

func (x *HTMLTag) PrintText(buf *bytes.Buffer) {}

"""



```