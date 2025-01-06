Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - The Big Picture:**

The first thing I noticed is the package name `markdown` and the file name `parse.go`. This strongly suggests the code is responsible for parsing Markdown text. The presence of comments like `// Copyright 2021 The Go Authors` and the package path `go/src/cmd/vendor/rsc.io/markdown` indicates it's part of a Go Markdown parsing library, likely used internally by Go tools or potentially as a standalone library. The presence of `rsc.io` hints at Russ Cox's involvement, a key figure in the Go project.

**2. Identifying Key Data Structures (The "Nouns"):**

I scanned the code for type definitions (`type`). The most prominent and seemingly fundamental type is `Block`. The comment preceding it lists several concrete types that implement `Block`: `CodeBLock`, `Document`, `Empty`, etc. This immediately tells me the code uses an interface-based approach to represent different Markdown block elements. This is a common pattern in parsers.

Other important types jumped out: `Position`, `mdState`, `buildState`, `blockBuilder`, `openBlock`, `itemBuilder`, `Text`, `Document`, `Parser`, and `parseState`. Each of these likely plays a specific role in the parsing process.

**3. Identifying Key Actions (The "Verbs"):**

Next, I looked for functions and methods. Key functions that signal actions or processes include:

* `PrintHTML`:  Indicates the ability to convert the parsed Markdown into HTML.
* `printMarkdown`: Suggests the ability to serialize the internal representation back to Markdown (potentially for debugging or other purposes).
* `Parse`:  The main entry point for parsing Markdown text.
* `addLine`: Processes a single line of input.
* `addBlock`, `closeBlock`, `doneBlock`:  Methods for managing the parsing stack and creating block elements.
* `extend`, `build`: Methods associated with `blockBuilder`, suggesting the process of recognizing and constructing block elements.
* `link`, `defineLink`:  Likely related to handling Markdown links.
* `newText`: Creates a `Text` block.

**4. Inferring Relationships and the Parsing Process:**

By looking at the types and methods together, I started to infer the parsing process:

* **Input:**  The `Parse` method takes a `string` as input, which is the Markdown text.
* **State Management:** The `parseState` struct seems to hold the current state of the parsing process, including the input text, current line number, the stack of open blocks (`stack`), and information about inline elements being parsed (`list`).
* **Block Stack:** The `stack` of `openBlock` suggests a stack-based parsing approach, where the parser keeps track of currently open Markdown block elements. This is typical for handling nested structures like lists and blockquotes.
* **Line Processing:**  The `addLine` function iterates through potential prefixes (`news`) to determine the type of block element starting on that line.
* **Block Building:** The `blockBuilder` interface and its implementors are responsible for recognizing and constructing specific block elements. The `extend` method likely handles multi-line block elements, and the `build` method finalizes the block construction.
* **Inline Processing:** The `Text` struct contains an `Inline` slice, and the `inline` method (mentioned in a comment) is likely responsible for parsing inline elements like emphasis, links, and code spans.
* **Output:** The `Parse` method returns a `Document` struct, which represents the root of the parsed Markdown structure and contains a slice of `Block` elements.

**5. Focusing on Specific Features and Potential Issues:**

I then looked at the `Parser` struct's fields. These represent configurable options that affect the parsing behavior: `HeadingIDs`, `Strikethrough`, `TaskListItems`, etc. This tells me the parser supports various Markdown extensions or flavors.

The comments within the code were also very helpful, especially the section at the beginning with questions about list processing. This gave clues about the challenges of parsing complex Markdown structures.

I considered potential error points for users. The configuration options in `Parser` seemed like a place where users might not understand the implications of enabling or disabling certain features. For example, if `Strikethrough` is false, `~abc~` won't be interpreted as strikethrough.

**6. Generating Examples (The "Show, Don't Just Tell"):**

To illustrate the functionality, I created basic Go code examples demonstrating how to use the `Parser` and how the configuration options affect the output. This makes the explanation much more concrete. I started with a simple example and then added variations to show the impact of different `Parser` settings.

**7. Explaining Command-Line Arguments (if applicable):**

Since the code didn't directly process command-line arguments, I noted that and explained why this section wasn't relevant in this specific case. It's important to address all parts of the prompt, even if it means stating that a particular aspect isn't present.

**8. Refining the Explanation (Clarity and Structure):**

Finally, I organized the information logically, using clear headings and bullet points to make the explanation easy to understand. I used precise language and avoided jargon where possible. I double-checked that I addressed all the requirements of the prompt.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level details of the parsing logic. I realized it's more important to start with a high-level overview of the functionality and then delve into specific aspects.
* I considered whether to explain the intricacies of the `openBlock` stack in detail. I decided against it for a general explanation, as it's more of an internal implementation detail. However, I mentioned its role in managing nested structures.
* I made sure to connect the code elements (types, functions) to their corresponding Markdown concepts (headings, lists, links).

By following this thought process, systematically examining the code, and focusing on the key elements and their relationships, I arrived at the comprehensive explanation provided previously.
这段代码是 Go 语言实现的 Markdown 解析器的一部分，主要负责将 Markdown 文本解析成内部的抽象语法树（AST），也就是由 `Block` 接口的不同实现组成的结构。

**功能列表:**

1. **定义了 Markdown 文档的抽象结构:**
   - `Block` 接口：定义了所有 Markdown 块级元素的通用行为，如获取位置信息 (`Pos()`)、打印 HTML (`PrintHTML`) 和打印 Markdown (`printMarkdown`)。
   - 具体的 `Block` 实现：代码中注释列出了一些 `Block` 接口的实现，例如 `CodeBLock`（代码块）、`Document`（文档根节点）、`Heading`（标题）、`List`（列表）、`Paragraph`（段落）等，虽然这段代码没有包含所有这些实现的具体定义。
   - `Document` 结构：代表整个 Markdown 文档，包含一个 `Block` 切片 (`Blocks`) 和一个链接定义映射 (`Links`)。

2. **实现了 Markdown 文本的解析过程:**
   - `Parser` 结构：是 Markdown 解析器的主要结构，包含解析配置选项（例如是否支持 Heading IDs、Strikethrough、TaskListItems 等）。
   - `parseState` 结构：在解析过程中维护解析器的状态，包括当前的文档根节点 (`root`)、链接定义 (`links`)、当前行号 (`lineno`)、打开的块元素栈 (`stack`) 等。
   - `addLine` 方法：负责处理输入的每一行文本，并根据 Markdown 语法规则添加到当前的块元素中或创建新的块元素。
   - `addBlock` 和 `closeBlock` 方法：用于管理块元素的层级关系，维护块元素栈。

3. **支持 Markdown 的一些扩展语法:**
   - `Parser` 结构体中的字段 `HeadingIDs`, `Strikethrough`, `TaskListItems` 等表明该解析器支持一些 Markdown 的扩展语法，例如为标题添加 ID、删除线、任务列表等。

4. **提供了将 AST 转换为 HTML 和 Markdown 的功能:**
   - `PrintHTML` 方法：`Block` 接口定义的方法，用于将块元素转换为 HTML 字符串。
   - `printMarkdown` 方法：`Block` 接口定义的方法，用于将块元素转换回 Markdown 字符串。
   - `ToHTML` 函数：接收一个 `Block` 并返回其 HTML 表示。
   - `ToMarkdown` 函数：接收一个 `Block` 并返回其 Markdown 表示。

5. **内部状态管理和辅助类型:**
   - `Position` 结构：存储块元素在源文本中的起始行号和结束行号。
   - `mdState` 结构：在打印 Markdown 时维护状态信息，例如前缀、缩进等。
   - `line` 结构：表示输入的一行文本，包含空格数、当前处理位置、文本内容等。
   - `blockBuilder` 接口和 `openBlock` 结构：用于在解析过程中构建块元素。

**推理出的 Go 语言功能实现 (带有代码示例):**

这段代码主要体现了以下 Go 语言功能的应用：

1. **接口 (`interface`):** `Block` 接口是核心，它定义了所有块级元素的通用行为，允许以统一的方式处理不同类型的块元素。

   ```go
   package main

   import "fmt"

   // 假设的 Block 接口和 Paragraph 实现
   type Block interface {
       Print()
   }

   type Paragraph struct {
       Text string
   }

   func (p *Paragraph) Print() {
       fmt.Println("<p>" + p.Text + "</p>")
   }

   func main() {
       var b Block = &Paragraph{Text: "这是一个段落。"}
       b.Print() // 输出: <p>这是一个段落。</p>
   }
   ```

2. **结构体 (`struct`):**  用于定义不同类型的 Markdown 元素和解析器的状态。例如 `Document` 存储了整个文档的信息，`parseState` 维护了解析过程中的状态。

   ```go
   package main

   import "fmt"

   type Document struct {
       Title  string
       Blocks []string // 假设 Blocks 是字符串切片
   }

   func main() {
       doc := Document{
           Title:  "我的文档",
           Blocks: []string{"第一段", "第二段"},
       }
       fmt.Println("文档标题:", doc.Title)
       fmt.Println("文档内容:", doc.Blocks)
   }
   ```

3. **方法 (`method`):**  与结构体关联的函数，用于实现特定类型的行为。例如 `Block` 接口的 `PrintHTML` 方法。

   ```go
   package main

   import "fmt"

   type Heading struct {
       Level int
       Text  string
   }

   func (h *Heading) PrintHTML() {
       fmt.Printf("<h%d>%s</h%d>\n", h.Level, h.Text, h.Level)
   }

   func main() {
       h := Heading{Level: 2, Text: "这是一个二级标题"}
       h.PrintHTML() // 输出: <h2>这是一个二级标题</h2>
   }
   ```

4. **切片 (`slice`):**  用于存储一系列相同类型的元素，例如 `Document` 中的 `Blocks` 切片用于存储文档中的所有块级元素。

5. **映射 (`map`):**  用于存储键值对，例如 `Document` 中的 `Links` 映射用于存储链接定义。

**代码推理示例 (假设输入与输出):**

假设我们有以下 Markdown 输入：

```markdown
# 标题一

这是一个段落。

- 列表项一
- 列表项二
```

根据代码的结构，`Parser.Parse()` 方法会接收这段文本，并逐步解析，最终构建一个 `Document` 类型的 AST。

**假设的内部 AST 结构 (简化版):**

```go
&Document{
    Position: Position{StartLine: 1, EndLine: 5},
    Blocks: []Block{
        &Heading{Position: Position{StartLine: 1, EndLine: 1}, Level: 1, Text: "标题一"},
        &Paragraph{Position: Position{StartLine: 3, EndLine: 3}, Inline: /* 代表 "这是一个段落。" 的 Inline 元素 */},
        &List{
            Position: Position{StartLine: 5, EndLine: 6},
            Items: []Block{
                &Item{Position: Position{StartLine: 5, EndLine: 5}, Inline: /* 代表 "列表项一" 的 Inline 元素 */},
                &Item{Position: Position{StartLine: 6, EndLine: 6}, Inline: /* 代表 "列表项二" 的 Inline 元素 */},
            },
        },
    },
    Links: map[string]*Link{},
}
```

如果调用 `ToHTML()` 函数并将这个 `Document` 传入，将会得到以下 HTML 输出：

```html
<h1>标题一</h1>
<p>这是一个段落。</p>
<ul>
<li>列表项一</li>
<li>列表项二</li>
</ul>
```

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。它是一个库，用于在 Go 程序中进行 Markdown 解析。如果需要从命令行读取 Markdown 文件并转换为 HTML，需要编写一个使用此库的 Go 程序，并在该程序中处理命令行参数。

例如，可以使用 `flag` 包来处理命令行参数：

```go
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"cmd/vendor/rsc.io/markdown" // 假设 markdown 库的路径
)

func main() {
	inputFilename := flag.String("input", "", "输入 Markdown 文件名")
	outputFilename := flag.String("output", "", "输出 HTML 文件名")
	flag.Parse()

	if *inputFilename == "" {
		fmt.Println("请指定输入文件")
		os.Exit(1)
	}

	content, err := ioutil.ReadFile(*inputFilename)
	if err != nil {
		fmt.Println("读取文件失败:", err)
		os.Exit(1)
	}

	parser := markdown.Parser{}
	doc := parser.Parse(string(content))
	html := markdown.ToHTML(doc)

	if *outputFilename == "" {
		fmt.Println(html)
	} else {
		err := ioutil.WriteFile(*outputFilename, []byte(html), 0644)
		if err != nil {
			fmt.Println("写入文件失败:", err)
			os.Exit(1)
		}
		fmt.Println("HTML 已写入:", *outputFilename)
	}
}
```

在这个示例中，`input` 和 `output` 是命令行参数，用于指定输入和输出文件名。

**使用者易犯错的点 (举例说明):**

使用者在使用这个 Markdown 解析库时，容易犯错的点可能在于对 `Parser` 的配置理解不足，导致解析结果与预期不符。

**示例：**

假设使用者期望解析带有删除线语法的 Markdown 文本，但忘记启用 `Strikethrough` 选项。

**输入 Markdown:**

```markdown
这是一个 ~删除线~ 文本。
```

**未启用 `Strikethrough` 的代码:**

```go
package main

import (
	"fmt"
	"cmd/vendor/rsc.io/markdown"
)

func main() {
	text := "这是一个 ~删除线~ 文本。"
	parser := markdown.Parser{} // 默认 Strikethrough 为 false
	doc := parser.Parse(text)
	html := markdown.ToHTML(doc)
	fmt.Println(html)
}
```

**输出 HTML (错误):**

```html
<p>这是一个 ~删除线~ 文本。</p>
```

**正确的代码 (启用 `Strikethrough`):**

```go
package main

import (
	"fmt"
	"cmd/vendor/rsc.io/markdown"
)

func main() {
	text := "这是一个 ~删除线~ 文本。"
	parser := markdown.Parser{Strikethrough: true}
	doc := parser.Parse(text)
	html := markdown.ToHTML(doc)
	fmt.Println(html)
}
```

**输出 HTML (正确):**

```html
<p>这是一个 <del>删除线</del> 文本。</p>
```

在这个例子中，使用者如果没有注意到 `Parser` 的配置选项，就可能得到错误的解析结果。因此，使用时需要仔细阅读文档或代码，了解各个配置选项的作用。

Prompt: 
```
这是路径为go/src/cmd/vendor/rsc.io/markdown/parse.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"fmt"
	"reflect"
	"slices"
	"strings"
)

/*

list block itself does not appear on stack?
item does
end of item returns block,
new item continues previous block if possible?

if close leaves lines or blocks behind, panic

close(b a list item, parent)
	if b's parent's last block is list && item can be added to it, do so
	else return new list

or maybe not parent but just current list of blocks

preserve LinkRefDefs?

*/

// Block is implemented by:
//
//	CodeBLock
//	Document
//	Empty
//	HTMLBlock
//	Heading
//	Item
//	List
//	Paragraph
//	Quote
//	Text
//	ThematicBreak
type Block interface {
	Pos() Position
	PrintHTML(buf *bytes.Buffer)
	printMarkdown(buf *bytes.Buffer, s mdState)
}

type mdState struct {
	prefix  string
	prefix1 string // for first line only
	bullet  rune   // for list items
	num     int    // for numbered list items
}

type Position struct {
	StartLine int
	EndLine   int
}

func (p Position) Pos() Position {
	return p
}

type buildState interface {
	blocks() []Block
	pos() Position
	last() Block
	deleteLast()

	link(label string) *Link
	defineLink(label string, link *Link)
	newText(pos Position, text string) *Text
}

type blockBuilder interface {
	extend(p *parseState, s line) (line, bool)
	build(buildState) Block
}

type openBlock struct {
	builder blockBuilder
	inner   []Block
	pos     Position
}

type itemBuilder struct {
	list        *listBuilder
	width       int
	haveContent bool
}

func (p *parseState) last() Block {
	ob := &p.stack[len(p.stack)-1]
	return ob.inner[len(ob.inner)-1]
}

func (p *parseState) deleteLast() {
	ob := &p.stack[len(p.stack)-1]
	ob.inner = ob.inner[:len(ob.inner)-1]
}

type Text struct {
	Position
	Inline []Inline
	raw    string
}

func (b *Text) PrintHTML(buf *bytes.Buffer) {
	for _, x := range b.Inline {
		x.PrintHTML(buf)
	}
}

func (b *Text) printMarkdown(buf *bytes.Buffer, s mdState) {
	if s.prefix1 != "" {
		buf.WriteString(s.prefix1)
	} else {
		buf.WriteString(s.prefix)
	}
	var prev Inline
	for _, x := range b.Inline {
		switch prev.(type) {
		case *SoftBreak, *HardBreak:
			buf.WriteString(s.prefix)
		}
		x.printMarkdown(buf)
		prev = x
	}
	buf.WriteByte('\n')
}

type rootBuilder struct{}

func (b *rootBuilder) build(p buildState) Block {
	return &Document{p.pos(), p.blocks(), p.(*parseState).links}
}

type Document struct {
	Position
	Blocks []Block
	Links  map[string]*Link
}

// A Parser is a Markdown parser.
// The exported fields in the struct can be filled in before calling
// [Parser.Parse] in order to customize the details of the parsing process.
// A Parser is safe for concurrent use by multiple goroutines.
type Parser struct {
	// HeadingIDs determines whether the parser accepts
	// the {#hdr} syntax for an HTML id="hdr" attribute on headings.
	// For example, if HeadingIDs is true then the Markdown
	//    ## Overview {#overview}
	// will render as the HTML
	//    <h2 id="overview">Overview</h2>
	HeadingIDs bool

	// Strikethrough determines whether the parser accepts
	// ~abc~ and ~~abc~~ as strikethrough syntax, producing
	// <del>abc</del> in HTML.
	Strikethrough bool

	// TaskListItems determines whether the parser accepts
	// “task list items” as defined in GitHub Flavored Markdown.
	// When a list item begins with the plain text [ ] or [x]
	// that turns into an unchecked or checked check box.
	TaskListItems bool

	// TODO
	AutoLinkText       bool
	AutoLinkAssumeHTTP bool

	// TODO
	Table bool

	// TODO
	Emoji bool

	// TODO
	SmartDot   bool
	SmartDash  bool
	SmartQuote bool
}

type parseState struct {
	*Parser

	root      *Document
	links     map[string]*Link
	lineno    int
	stack     []openBlock
	lineDepth int

	corner bool // noticed corner case to ignore in cross-implementation testing

	// inlines
	s       string
	emitted int // s[:emitted] has been emitted into list
	list    []Inline

	// for fixup at end
	lists []*List
	texts []*Text

	backticks backtickParser
}

func (p *parseState) newText(pos Position, text string) *Text {
	b := &Text{Position: pos, raw: text}
	p.texts = append(p.texts, b)
	return b
}

func (p *parseState) blocks() []Block {
	b := &p.stack[len(p.stack)-1]
	return b.inner
}

func (p *parseState) pos() Position {
	b := &p.stack[len(p.stack)-1]
	return b.pos
}

func (p *Parser) Parse(text string) *Document {
	d, _ := p.parse(text)
	return d
}

func (p *Parser) parse(text string) (d *Document, corner bool) {
	var ps parseState
	ps.Parser = p
	if strings.Contains(text, "\x00") {
		text = strings.ReplaceAll(text, "\x00", "\uFFFD")
		ps.corner = true // goldmark does not replace NUL
	}

	ps.lineDepth = -1
	ps.addBlock(&rootBuilder{})
	for text != "" {
		var ln string
		i := strings.Index(text, "\n")
		j := strings.Index(text, "\r")
		var nl byte
		switch {
		case j >= 0 && (i < 0 || j < i): // have \r, maybe \r\n
			ln = text[:j]
			if i == j+1 {
				text = text[j+2:]
				nl = '\r' + '\n'
			} else {
				text = text[j+1:]
				nl = '\r'
			}
		case i >= 0:
			ln, text = text[:i], text[i+1:]
			nl = '\n'
		default:
			ln, text = text, ""
		}
		ps.lineno++
		ps.addLine(line{text: ln, nl: nl})
	}
	ps.trimStack(0)

	for _, t := range ps.texts {
		t.Inline = ps.inline(t.raw)
	}

	if p.TaskListItems {
		for _, list := range ps.lists {
			ps.taskList(list)
		}
	}

	return ps.root, ps.corner
}

func (p *parseState) curB() blockBuilder {
	if p.lineDepth < len(p.stack) {
		return p.stack[p.lineDepth].builder
	}
	return nil
}

func (p *parseState) nextB() blockBuilder {
	if p.lineDepth+1 < len(p.stack) {
		return p.stack[p.lineDepth+1].builder
	}
	return nil
}
func (p *parseState) trimStack(depth int) {
	if len(p.stack) < depth {
		panic("trimStack")
	}
	for len(p.stack) > depth {
		p.closeBlock()
	}
}

func (p *parseState) addBlock(c blockBuilder) {
	p.trimStack(p.lineDepth + 1)
	p.stack = append(p.stack, openBlock{})
	ob := &p.stack[len(p.stack)-1]
	ob.builder = c
	ob.pos.StartLine = p.lineno
	ob.pos.EndLine = p.lineno
}

func (p *parseState) doneBlock(b Block) {
	p.trimStack(p.lineDepth + 1)
	ob := &p.stack[len(p.stack)-1]
	ob.inner = append(ob.inner, b)
}

func (p *parseState) para() *paraBuilder {
	if b, ok := p.stack[len(p.stack)-1].builder.(*paraBuilder); ok {
		return b
	}
	return nil
}

func (p *parseState) closeBlock() Block {
	b := &p.stack[len(p.stack)-1]
	if b.builder == nil {
		println("closeBlock", len(p.stack)-1)
	}
	blk := b.builder.build(p)
	if list, ok := blk.(*List); ok {
		p.corner = p.corner || listCorner(list)
		if p.TaskListItems {
			p.lists = append(p.lists, list)
		}
	}
	p.stack = p.stack[:len(p.stack)-1]
	if len(p.stack) > 0 {
		b := &p.stack[len(p.stack)-1]
		b.inner = append(b.inner, blk)
		// _ = b
	} else {
		p.root = blk.(*Document)
	}
	return blk
}

func (p *parseState) link(label string) *Link {
	return p.links[label]
}

func (p *parseState) defineLink(label string, link *Link) {
	if p.links == nil {
		p.links = make(map[string]*Link)
	}
	p.links[label] = link
}

type line struct {
	spaces int
	i      int
	tab    int
	text   string
	nl     byte // newline character ending this line: \r or \n or zero for EOF
}

func (p *parseState) addLine(s line) {
	// Process continued prefixes.
	p.lineDepth = 0
	for ; p.lineDepth+1 < len(p.stack); p.lineDepth++ {
		old := s
		var ok bool
		s, ok = p.stack[p.lineDepth+1].builder.extend(p, s)
		if !old.isBlank() && (ok || s != old) {
			p.stack[p.lineDepth+1].pos.EndLine = p.lineno
		}
		if !ok {
			break
		}
	}

	if s.isBlank() {
		p.trimStack(p.lineDepth + 1)
		return
	}

	// Process new prefixes, if any.
Prefixes:
	// Start new block inside p.stack[depth].
	for _, fn := range news {
		if l, ok := fn(p, s); ok {
			s = l
			if s.isBlank() {
				return
			}
			p.lineDepth++
			goto Prefixes
		}
	}

	newPara(p, s)
}

func (c *rootBuilder) extend(p *parseState, s line) (line, bool) {
	panic("root extend")
}

var news = []func(*parseState, line) (line, bool){
	newQuote,
	newATXHeading,
	newSetextHeading,
	newHR,
	newListItem,
	newHTML,
	newFence,
	newPre,
}

func (s *line) peek() byte {
	if s.spaces > 0 {
		return ' '
	}
	if s.i >= len(s.text) {
		return 0
	}
	return s.text[s.i]
}

func (s *line) skipSpace() {
	s.spaces = 0
	for s.i < len(s.text) && (s.text[s.i] == ' ' || s.text[s.i] == '\t') {
		s.i++
	}
}

func (s *line) trimSpace(min, max int, eolOK bool) bool {
	t := *s
	for n := 0; n < max; n++ {
		if t.spaces > 0 {
			t.spaces--
			continue
		}
		if t.i >= len(t.text) && eolOK {
			continue
		}
		if t.i < len(t.text) {
			switch t.text[t.i] {
			case '\t':
				t.spaces = 4 - (t.i-t.tab)&3 - 1
				t.i++
				t.tab = t.i
				continue
			case ' ':
				t.i++
				continue
			}
		}
		if n >= min {
			break
		}
		return false
	}
	*s = t
	return true
}

func (s *line) trim(c byte) bool {
	if s.spaces > 0 {
		if c == ' ' {
			s.spaces--
			return true
		}
		return false
	}
	if s.i < len(s.text) && s.text[s.i] == c {
		s.i++
		return true
	}
	return false
}

func (s *line) string() string {
	switch s.spaces {
	case 0:
		return s.text[s.i:]
	case 1:
		return " " + s.text[s.i:]
	case 2:
		return "  " + s.text[s.i:]
	case 3:
		return "   " + s.text[s.i:]
	}
	panic("bad spaces")
}

func trimLeftSpaceTab(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return s[i:]
}

func trimRightSpaceTab(s string) string {
	j := len(s)
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[:j]
}

func trimSpaceTab(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	s = s[i:]
	j := len(s)
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[:j]
}

func trimSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	s = s[i:]
	j := len(s)
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[:j]
}

func trimSpaceTabNewline(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
		i++
	}
	s = s[i:]
	j := len(s)
	for j > 0 && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\n') {
		j--
	}
	return s[:j]
}

func (s *line) isBlank() bool {
	return trimLeftSpaceTab(s.text[s.i:]) == ""
}

func (s *line) eof() bool {
	return s.i >= len(s.text)
}

func (s *line) trimSpaceString() string {
	return trimLeftSpaceTab(s.text[s.i:])
}

func (s *line) trimString() string {
	return trimSpaceTab(s.text[s.i:])
}

func ToHTML(b Block) string {
	var buf bytes.Buffer
	b.PrintHTML(&buf)
	return buf.String()
}

func ToMarkdown(b Block) string {
	var buf bytes.Buffer
	b.printMarkdown(&buf, mdState{})
	s := buf.String()
	// Remove final extra newline.
	if strings.HasSuffix(s, "\n\n") {
		s = s[:len(s)-1]
	}
	return s
}

func (b *Document) PrintHTML(buf *bytes.Buffer) {
	for _, c := range b.Blocks {
		c.PrintHTML(buf)
	}
}

func (b *Document) printMarkdown(buf *bytes.Buffer, s mdState) {
	printMarkdownBlocks(b.Blocks, buf, s)
	// Print links sorted by keys for deterministic output.
	var keys []string
	for k := range b.Links {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		l := b.Links[k]
		fmt.Fprintf(buf, "[%s]: %s", k, l.URL)
		printLinkTitleMarkdown(buf, l.Title, l.TitleChar)
		buf.WriteByte('\n')
	}
}

func printMarkdownBlocks(bs []Block, buf *bytes.Buffer, s mdState) {
	prevEnd := 0
	for _, b := range bs {
		// Preserve blank lines between blocks.
		if prevEnd > 0 {
			for i := prevEnd + 1; i < b.Pos().StartLine; i++ {
				buf.WriteString(trimRightSpaceTab(s.prefix))
				buf.WriteByte('\n')
			}
		}
		b.printMarkdown(buf, s)
		prevEnd = b.Pos().EndLine
		s.prefix1 = "" // item prefix only for first block
	}
}

var (
	blockType   = reflect.TypeOf(new(Block)).Elem()
	blocksType  = reflect.TypeOf(new([]Block)).Elem()
	inlinesType = reflect.TypeOf(new([]Inline)).Elem()
)

func printb(buf *bytes.Buffer, b Block, prefix string) {
	fmt.Fprintf(buf, "(%T", b)
	v := reflect.ValueOf(b)
	v = reflect.Indirect(v)
	if v.Kind() != reflect.Struct {
		fmt.Fprintf(buf, " %v", b)
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tf := t.Field(i)
		if !tf.IsExported() {
			continue
		}
		if tf.Type == inlinesType {
			printis(buf, v.Field(i).Interface().([]Inline))
		} else if tf.Type.Kind() == reflect.Slice && tf.Type.Elem().Kind() == reflect.String {
			fmt.Fprintf(buf, " %s:%q", tf.Name, v.Field(i))
		} else if tf.Type != blocksType && !tf.Type.Implements(blockType) && tf.Type.Kind() != reflect.Slice {
			fmt.Fprintf(buf, " %s:%v", tf.Name, v.Field(i))
		}
	}

	prefix += "\t"
	for i := 0; i < t.NumField(); i++ {
		tf := t.Field(i)
		if !tf.IsExported() {
			continue
		}
		if tf.Type.Implements(blockType) {
			fmt.Fprintf(buf, "\n%s", prefix)
			printb(buf, v.Field(i).Interface().(Block), prefix)
		} else if tf.Type == blocksType {
			vf := v.Field(i)
			for i := 0; i < vf.Len(); i++ {
				fmt.Fprintf(buf, "\n%s", prefix)
				printb(buf, vf.Index(i).Interface().(Block), prefix)
			}
		} else if tf.Type.Kind() == reflect.Slice && tf.Type != inlinesType && tf.Type.Elem().Kind() != reflect.String {
			fmt.Fprintf(buf, "\n%s%s:", prefix, t.Field(i).Name)
			printslice(buf, v.Field(i), prefix)
		}
	}
	fmt.Fprintf(buf, ")")
}

func printslice(buf *bytes.Buffer, v reflect.Value, prefix string) {
	if v.Type().Elem().Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			fmt.Fprintf(buf, "\n%s#%d:", prefix, i)
			printslice(buf, v.Index(i), prefix+"\t")
		}
		return
	}
	for i := 0; i < v.Len(); i++ {
		fmt.Fprintf(buf, " ")
		printb(buf, v.Index(i).Interface().(Block), prefix+"\t")
	}
}

func printi(buf *bytes.Buffer, in Inline) {
	fmt.Fprintf(buf, "%T(", in)
	v := reflect.ValueOf(in).Elem()
	text := v.FieldByName("Text")
	if text.IsValid() {
		fmt.Fprintf(buf, "%q", text)
	}
	inner := v.FieldByName("Inner")
	if inner.IsValid() {
		printis(buf, inner.Interface().([]Inline))
	}
	buf.WriteString(")")
}

func printis(buf *bytes.Buffer, ins []Inline) {
	for _, in := range ins {
		buf.WriteByte(' ')
		printi(buf, in)
	}
}

func dump(b Block) string {
	var buf bytes.Buffer
	printb(&buf, b, "")
	return buf.String()
}

"""



```