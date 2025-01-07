Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Purpose:** The first step is to understand the overarching goal of this code. The package name `markdown` and the file name `table.go` strongly suggest this code is responsible for handling Markdown tables. The presence of types like `Table`, `tableBuilder`, and functions like `isTableStart` further confirms this.

2. **Deconstruct the Code (Top-Down):**  Start by looking at the major types and their methods.

    * **`tableTrimmed`:** This is a type alias for `string`. It seems like it's used to represent table rows/cells after some initial trimming. The name suggests removing leading/trailing characters.

    * **Helper Functions:**  Functions like `isTableSpace`, `tableTrimSpace`, `tableTrimOuter`, `tableCount`, `tableUnescape`, and `tableAlign` appear to be utility functions for manipulating strings related to tables. It's worth noting what each of these specifically does (trimming, counting columns, handling escape characters, determining alignment).

    * **`isTableStart`:** This is a crucial function. Its name suggests it determines if a given header and delimiter line mark the beginning of a Markdown table. The logic inside needs closer inspection to understand the criteria.

    * **`tableBuilder`:** This struct seems designed to accumulate information about a table (header, delimiter, rows) before constructing the final `Table` object. The methods `start` and `addRow` confirm this.

    * **`Table`:** This struct likely represents the parsed Markdown table. It contains the header, alignment information, and the table rows as structured data.

    * **`PrintHTML` and `printMarkdown`:** These methods are responsible for rendering the `Table` into different formats. The provided code only includes the HTML rendering. The presence of both hints at a broader Markdown processing context.

    * **`build`:** This method of `tableBuilder` takes the collected information and constructs the `Table` object. It uses `parseRow` and `parseAlign`.

    * **`parseRow`:** This function is responsible for splitting a table row string into individual cells (`Text` objects). It handles escaped pipes (`\|`).

    * **`parseAlign`:** This function analyzes the delimiter row to determine the alignment of each column.

3. **Focus on Key Functionality and Logic:**

    * **Table Recognition (`isTableStart`):** The logic here is important. It checks if the delimiter line has the correct structure (optional colons for alignment, hyphens). It also verifies that the number of columns in the header and delimiter match. The edge case of a single "|" is explicitly handled (and rejected).

    * **Parsing Rows (`parseRow`):** Pay attention to how cells are delimited by `|`, how escaped pipes are handled, and how missing cells are treated.

    * **Determining Alignment (`parseAlign` and `tableAlign`):**  Understand how the colons in the delimiter line are used to determine left, right, and center alignment.

4. **Infer Context and Purpose:** Based on the code structure and function names, it's clear this code is part of a larger Markdown processing library. It focuses specifically on parsing and representing tables according to the CommonMark (or a similar) specification.

5. **Illustrate with Examples:**  To demonstrate the functionality, create simple Markdown table inputs and predict how the code would process them. This helps solidify understanding and provides concrete examples. Think about different alignment scenarios, empty cells, and escaped characters.

6. **Identify Potential Pitfalls:** Consider how a user might misuse this functionality or encounter unexpected behavior. For instance, forgetting the delimiter line or having inconsistent column counts would lead to incorrect parsing.

7. **Structure the Answer:** Organize the findings into clear categories: functionality, Go language features, code reasoning (with examples), handling command-line arguments (if applicable, in this case not directly), and common mistakes.

8. **Refine and Review:** Read through the answer to ensure clarity, accuracy, and completeness. Make sure the Go code examples are valid and illustrate the points effectively. Check for any inconsistencies or areas that could be explained better.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe `tableTrimmed` is more complex than just a string. **Correction:**  Upon closer inspection, it's just a type alias, primarily used for semantic clarity and potentially to attach methods later (though none are shown in this snippet).
* **Initial thought:**  The code might directly interact with file I/O. **Correction:**  The provided snippet operates on strings. The larger Markdown library would handle file input.
* **Missed detail:** Initially, I might have overlooked the handling of escaped pipes (`\|`). **Correction:**  Reviewing the `parseRow` and `tableUnescape` functions highlights this important detail.
* **Overemphasis on command-line arguments:** I might initially look for command-line argument processing. **Correction:** This snippet is a library component and doesn't directly handle command-line arguments. The focus should be on its core table parsing logic.

By following this structured approach, involving decomposition, logical analysis, example creation, and iterative refinement, we can effectively understand and explain the functionality of the given Go code.
这段代码是 Go 语言中一个用于解析和处理 Markdown 表格的实现。它属于一个 Markdown 解析库的一部分，专门负责识别、解析和表示 Markdown 格式的表格。

以下是代码的主要功能：

1. **识别表格的开始 (`isTableStart` 函数):**  该函数判断给定的两行文本（通常是表格的表头行和分隔行）是否构成一个有效的 Markdown 表格的开头。它会检查分隔行是否符合表格分隔线的格式，例如包含至少三个连字符 `-`，并且列数与表头行匹配。分隔行还可以包含冒号 `:` 来指示列的对齐方式。

2. **计算表格的列数 (`tableCount` 函数):**  给定一个表格行（去除首尾的 `|`），该函数计算该行包含的列数，通过统计分隔符 `|` 的数量来实现。会忽略被反斜杠转义的 `\|`。

3. **修剪表格行 (`tableTrimSpace`, `tableTrimOuter` 函数):**
   - `tableTrimSpace` 函数用于去除字符串首尾的空格、制表符、垂直制表符和换页符。
   - `tableTrimOuter` 函数在 `tableTrimSpace` 的基础上，还会去除表格行首尾的可选 `|` 字符。

4. **构建表格结构 (`tableBuilder` 结构体和相关方法):**
   - `tableBuilder` 结构体用于逐步构建表格的信息。
   - `start` 方法用于初始化 `tableBuilder`，记录表头和分隔行。
   - `addRow` 方法用于添加表格的每一行数据。
   - `build` 方法根据收集到的表头、分隔行和数据行，创建一个 `Table` 结构体的实例。

5. **表示表格 (`Table` 结构体):** `Table` 结构体用于存储解析后的表格信息，包括：
   - `Position`:  记录表格在原始 Markdown 文本中的位置信息。
   - `Header`:  一个 `Text` 类型的切片，存储表头单元格的内容。
   - `Align`:  一个字符串切片，存储每一列的对齐方式（"l" 表示左对齐, "c" 表示居中对齐, "r" 表示右对齐, "" 表示未设置）。
   - `Rows`:  一个二维的 `Text` 类型的切片，存储表格的每一行数据，每一行又是一个 `Text` 类型的切片，表示该行的单元格内容。

6. **渲染为 HTML (`PrintHTML` 方法):** `PrintHTML` 方法将 `Table` 结构体表示的表格渲染成 HTML 的 `<table>` 元素，包括 `<thead>` 和 `<tbody>`，并根据 `Align` 信息设置列的对齐方式。

7. **解析表格行 (`parseRow` 方法):** 该方法将一个表格数据行字符串分割成多个 `Text` 类型的单元格。它会处理转义的 `\|`，并将额外的单元格丢弃，缺失的单元格填充为空字符串。

8. **解析对齐方式 (`parseAlign` 和 `tableAlign` 函数):**
   - `parseAlign` 方法解析分隔行，提取每一列的对齐信息。
   - `tableAlign` 函数根据分隔行中单元格的内容（例如 `:---`, `---:`, `:---:`）来判断列的对齐方式。

9. **取消转义 (`tableUnescape` 函数):**  用于移除表格单元格内容中为了表示字面量 `|` 而添加的反斜杠 `\`。

**它可以看作是 Markdown 解析器中处理表格语法的核心组件。**

**Go 代码示例说明:**

假设我们有以下 Markdown 表格：

```markdown
| Header 1 | Header 2 |
| -------- | -------- |
| Cell 1   | Cell 2   |
| Cell 3   | Cell 4   |
```

以下是如何使用这段代码（假设在一个更大的 Markdown 解析流程中）：

```go
package main

import (
	"bytes"
	"fmt"
	"strings"
)

// 假设这是从 vendor/rsc.io/markdown/table.go 中复制出来的代码
type tableTrimmed string

func isTableSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\v' || c == '\f'
}

func tableTrimSpace(s string) string {
	i := 0
	for i < len(s) && isTableSpace(s[i]) {
		i++
	}
	j := len(s)
	for j > i && isTableSpace(s[j-1]) {
		j--
	}
	return s[i:j]
}

func tableTrimOuter(row string) tableTrimmed {
	row = tableTrimSpace(row)
	if len(row) > 0 && row[0] == '|' {
		row = row[1:]
	}
	if len(row) > 0 && row[len(row)-1] == '|' {
		row = row[:len(row)-1]
	}
	return tableTrimmed(row)
}

func isTableStart(hdr1, delim1 string) bool {
	col := 0
	delim := tableTrimOuter(delim1)
	i := 0
	for ; ; col++ {
		for i < len(delim) && isTableSpace(delim[i]) {
			i++
		}
		if i >= len(delim) {
			break
		}
		if i < len(delim) && delim[i] == ':' {
			i++
		}
		if i >= len(delim) || delim[i] != '-' {
			return false
		}
		i++
		for i < len(delim) && delim[i] == '-' {
			i++
		}
		if i < len(delim) && delim[i] == ':' {
			i++
		}
		for i < len(delim) && isTableSpace(delim[i]) {
			i++
		}
		if i < len(delim) && delim[i] == '|' {
			i++
		}
	}

	if strings.TrimSpace(hdr1) == "|" {
		return false
	}

	return col == tableCount(tableTrimOuter(hdr1))
}

func tableCount(row tableTrimmed) int {
	col := 1
	prev := byte(0)
	for i := 0; i < len(row); i++ {
		c := row[i]
		if c == '|' && prev != '\\' {
			col++
		}
		prev = c
	}
	return col
}

type tableBuilder struct {
	hdr   tableTrimmed
	delim tableTrimmed
	rows  []tableTrimmed
}

func (b *tableBuilder) start(hdr, delim string) {
	b.hdr = tableTrimOuter(hdr)
	b.delim = tableTrimOuter(delim)
}

func (b *tableBuilder) addRow(row string) {
	b.rows = append(b.rows, tableTrimOuter(row))
}

type Position struct {
	StartLine int
	EndLine   int
}

type Text struct {
	Position Position
	Content  string
}

type Table struct {
	Position Position
	Header []*Text
	Align  []string
	Rows   [][]*Text
}

func (t *Table) PrintHTML(buf *bytes.Buffer) {
	buf.WriteString("<table>\n")
	buf.WriteString("<thead>\n")
	buf.WriteString("<tr>\n")
	for i, hdr := range t.Header {
		buf.WriteString("<th")
		if t.Align[i] != "" {
			buf.WriteString(" align=\"")
			buf.WriteString(t.Align[i])
			buf.WriteString("\"")
		}
		buf.WriteString(">")
		hdr.PrintHTML(buf)
		buf.WriteString("</th>\n")
	}
	buf.WriteString("</tr>\n")
	buf.WriteString("</thead>\n")
	if len(t.Rows) > 0 {
		buf.WriteString("<tbody>\n")
		for _, row := range t.Rows {
			buf.WriteString("<tr>\n")
			for i, cell := range row {
				buf.WriteString("<td")
				if i < len(t.Align) && t.Align[i] != "" {
					buf.WriteString(" align=\"")
					buf.WriteString(t.Align[i])
					buf.WriteString("\"")
				}
				buf.WriteString(">")
				cell.PrintHTML(buf)
				buf.WriteString("</td>\n")
			}
			buf.WriteString("</tr>\n")
		}
		buf.WriteString("</tbody>\n")
	}
	buf.WriteString("</table>\n")
}

func (t *Text) PrintHTML(buf *bytes.Buffer) {
	buf.WriteString(t.Content)
}

func (b *tableBuilder) build(p buildState) Block {
	pos := p.pos()
	pos.StartLine--
	pos.EndLine = pos.StartLine + 1 + len(b.rows)
	t := &Table{
		Position: pos,
	}
	width := tableCount(b.hdr)
	t.Header = b.parseRow(p, b.hdr, pos.StartLine, width)
	t.Align = b.parseAlign(b.delim, width)
	t.Rows = make([][]*Text, len(b.rows))
	for i, row := range b.rows {
		t.Rows[i] = b.parseRow(p, row, pos.StartLine+2+i, width)
	}
	return t
}

func (b *tableBuilder) parseRow(p buildState, row tableTrimmed, line int, width int) []*Text {
	out := make([]*Text, 0, width)
	pos := Position{StartLine: line, EndLine: line}
	start := 0
	unesc := nop
	for i := 0; i < len(row); i++ {
		c := row[i]
		if c == '\\' && i+1 < len(row) && row[i+1] == '|' {
			unesc = tableUnescape
			i++
			continue
		}
		if c == '|' {
			out = append(out, p.newText(pos, unesc(strings.Trim(string(row[start:i]), " \t\v\f"))))
			if len(out) == width {
				return out
			}
			start = i + 1
			unesc = nop
		}
	}
	out = append(out, p.newText(pos, unesc(strings.Trim(string(row[start:]), " \t\v\f"))))
	for len(out) < width {
		out = append(out, p.newText(pos, ""))
	}
	return out
}

func nop(text string) string {
	return text
}

func tableUnescape(text string) string {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\\' && i+1 < len(text) && text[i+1] == '|' {
			i++
			c = '|'
		}
		out = append(out, c)
	}
	return string(out)
}

func (b *tableBuilder) parseAlign(delim tableTrimmed, n int) []string {
	align := make([]string, 0, tableCount(delim))
	start := 0
	for i := 0; i < len(delim); i++ {
		if delim[i] == '|' {
			align = append(align, tableAlign(string(delim[start:i])))
			start = i + 1
		}
	}
	align = append(align, tableAlign(string(delim[start:])))
	return align
}

func tableAlign(cell string) string {
	cell = tableTrimSpace(cell)
	l := cell[0] == ':'
	r := cell[len(cell)-1] == ':'
	switch {
	case l && r:
		return "center"
	case l:
		return "left"
	case r:
		return "right"
	}
	return ""
}

// 模拟 buildState 和 Block 接口
type buildState interface {
	pos() Position
	newText(pos Position, content string) *Text
}

type Block interface{}

type myBuildState struct {
	currentLine int
}

func (m *myBuildState) pos() Position {
	return Position{StartLine: m.currentLine, EndLine: m.currentLine}
}

func (m *myBuildState) newText(pos Position, content string) *Text {
	return &Text{Position: pos, Content: content}
}

func main() {
	markdown := `| Header 1 | Header 2 |
| -------- | -------- |
| Cell 1   | Cell 2   |
| Cell 3   | Cell 4   |`

	lines := strings.Split(markdown, "\n")
	if len(lines) < 2 {
		return
	}

	hdr := lines[0]
	delim := lines[1]

	if isTableStart(hdr, delim) {
		builder := &tableBuilder{}
		builder.start(hdr, delim)
		for _, row := range lines[2:] {
			builder.addRow(row)
		}

		// 模拟 buildState
		bs := &myBuildState{currentLine: 1}

		tableBlock := builder.build(bs)
		if table, ok := tableBlock.(*Table); ok {
			var htmlBuf bytes.Buffer
			table.PrintHTML(&htmlBuf)
			fmt.Println(htmlBuf.String())
		}
	}
}
```

**假设的输入与输出:**

**输入 (Markdown 字符串):**

```markdown
| Name   | Age | City    |
| ------ | --- | :-----: |
| Alice  | 30  | New York|
| Bob    | 25  | London  |
```

**输出 (HTML 字符串):**

```html
<table>
<thead>
<tr>
<th>Name</th>
<th>Age</th>
<th align="center">City</th>
</tr>
</thead>
<tbody>
<tr>
<td>Alice</td>
<td>30</td>
<td>New York</td>
</tr>
<tr>
<td>Bob</td>
<td>25</td>
<td>London</td>
</tr>
</tbody>
</table>
```

**代码推理:**

在 `main` 函数的示例中，我们首先判断前两行是否构成表格的开始。如果 `isTableStart` 返回 `true`，则创建一个 `tableBuilder` 并逐行添加数据。最后调用 `build` 方法创建一个 `Table` 对象，并使用 `PrintHTML` 方法将其渲染成 HTML。`parseAlign` 函数会根据分隔行的 `:-----:` 识别出 "City" 列需要居中对齐。

**命令行参数的具体处理:**

这段代码本身不涉及任何命令行参数的处理。它是一个库的内部实现，专注于解析 Markdown 文本中的表格结构。命令行参数的处理通常会在调用此库的更上层应用中进行。

**使用者易犯错的点:**

1. **忘记或错误地编写分隔行:** 分隔行是识别表格的关键。如果分隔行缺失、格式不正确（例如少于三个连字符，列数与表头不匹配），则表格将不会被识别。

   **错误示例:**

   ```markdown
   | Header 1 | Header 2 |
   | Header 1 content | Header 2 content |
   ```

   这段 Markdown 不会被识别为表格，因为缺少了分隔行。

2. **分隔行和表头行的列数不一致:**  `isTableStart` 函数会检查分隔行和表头行的列数是否匹配。如果列数不一致，表格也不会被识别。

   **错误示例:**

   ```markdown
   | Header 1 | Header 2 |
   | -------- |
   ```

   这里表头有两列，但分隔行只定义了一列，导致无法正确解析。

3. **在表格单元格中使用未转义的 `|`:** 如果需要在表格单元格中显示字面量的 `|` 字符，需要使用 `\|` 进行转义。否则，解析器会将其误认为列分隔符。

   **错误示例:**

   ```markdown
   | A | B |
   | - | - |
   | Value with | in it | Other value |
   ```

   这里 "Value with | in it" 会被解析成两个单元格。正确的写法是 "Value with \| in it"。

4. **误认为只有表头和分隔行的就能构成表格:** 至少需要一行数据行才能让 `<tbody>` 部分在 HTML 输出中显示。

   **易错示例:**

   ```markdown
   | Header 1 | Header 2 |
   | -------- | -------- |
   ```

   虽然这会被识别为表格，但生成的 HTML 将只包含 `<thead>`，而没有 `<tbody>`。

这段代码的核心职责是准确地将 Markdown 表格的文本表示转换为结构化的数据，以便后续进行渲染或其他处理。理解其功能有助于开发者在使用 Markdown 解析库时正确地编写和处理表格。

Prompt: 
```
这是路径为go/src/cmd/vendor/rsc.io/markdown/table.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package markdown

import (
	"bytes"
	"strings"
)

type tableTrimmed string

func isTableSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\v' || c == '\f'
}

func tableTrimSpace(s string) string {
	i := 0
	for i < len(s) && isTableSpace(s[i]) {
		i++
	}
	j := len(s)
	for j > i && isTableSpace(s[j-1]) {
		j--
	}
	return s[i:j]
}

func tableTrimOuter(row string) tableTrimmed {
	row = tableTrimSpace(row)
	if len(row) > 0 && row[0] == '|' {
		row = row[1:]
	}
	if len(row) > 0 && row[len(row)-1] == '|' {
		row = row[:len(row)-1]
	}
	return tableTrimmed(row)
}

func isTableStart(hdr1, delim1 string) bool {
	// Scan potential delimiter string, counting columns.
	// This happens on every line of text,
	// so make it relatively quick - nothing expensive.
	col := 0
	delim := tableTrimOuter(delim1)
	i := 0
	for ; ; col++ {
		for i < len(delim) && isTableSpace(delim[i]) {
			i++
		}
		if i >= len(delim) {
			break
		}
		if i < len(delim) && delim[i] == ':' {
			i++
		}
		if i >= len(delim) || delim[i] != '-' {
			return false
		}
		i++
		for i < len(delim) && delim[i] == '-' {
			i++
		}
		if i < len(delim) && delim[i] == ':' {
			i++
		}
		for i < len(delim) && isTableSpace(delim[i]) {
			i++
		}
		if i < len(delim) && delim[i] == '|' {
			i++
		}
	}

	if strings.TrimSpace(hdr1) == "|" {
		// https://github.com/github/cmark-gfm/pull/127 and
		// https://github.com/github/cmark-gfm/pull/128
		// fixed a buffer overread by rejecting | by itself as a table line.
		// That seems to violate the spec, but we will play along.
		return false
	}

	return col == tableCount(tableTrimOuter(hdr1))
}

func tableCount(row tableTrimmed) int {
	col := 1
	prev := byte(0)
	for i := 0; i < len(row); i++ {
		c := row[i]
		if c == '|' && prev != '\\' {
			col++
		}
		prev = c
	}
	return col
}

type tableBuilder struct {
	hdr   tableTrimmed
	delim tableTrimmed
	rows  []tableTrimmed
}

func (b *tableBuilder) start(hdr, delim string) {
	b.hdr = tableTrimOuter(hdr)
	b.delim = tableTrimOuter(delim)
}

func (b *tableBuilder) addRow(row string) {
	b.rows = append(b.rows, tableTrimOuter(row))
}

type Table struct {
	Position
	Header []*Text
	Align  []string // 'l', 'c', 'r' for left, center, right; 0 for unset
	Rows   [][]*Text
}

func (t *Table) PrintHTML(buf *bytes.Buffer) {
	buf.WriteString("<table>\n")
	buf.WriteString("<thead>\n")
	buf.WriteString("<tr>\n")
	for i, hdr := range t.Header {
		buf.WriteString("<th")
		if t.Align[i] != "" {
			buf.WriteString(" align=\"")
			buf.WriteString(t.Align[i])
			buf.WriteString("\"")
		}
		buf.WriteString(">")
		hdr.PrintHTML(buf)
		buf.WriteString("</th>\n")
	}
	buf.WriteString("</tr>\n")
	buf.WriteString("</thead>\n")
	if len(t.Rows) > 0 {
		buf.WriteString("<tbody>\n")
		for _, row := range t.Rows {
			buf.WriteString("<tr>\n")
			for i, cell := range row {
				buf.WriteString("<td")
				if i < len(t.Align) && t.Align[i] != "" {
					buf.WriteString(" align=\"")
					buf.WriteString(t.Align[i])
					buf.WriteString("\"")
				}
				buf.WriteString(">")
				cell.PrintHTML(buf)
				buf.WriteString("</td>\n")
			}
			buf.WriteString("</tr>\n")
		}
		buf.WriteString("</tbody>\n")
	}
	buf.WriteString("</table>\n")
}

func (t *Table) printMarkdown(buf *bytes.Buffer, s mdState) {
}

func (b *tableBuilder) build(p buildState) Block {
	pos := p.pos()
	pos.StartLine-- // builder does not count header
	pos.EndLine = pos.StartLine + 1 + len(b.rows)
	t := &Table{
		Position: pos,
	}
	width := tableCount(b.hdr)
	t.Header = b.parseRow(p, b.hdr, pos.StartLine, width)
	t.Align = b.parseAlign(b.delim, width)
	t.Rows = make([][]*Text, len(b.rows))
	for i, row := range b.rows {
		t.Rows[i] = b.parseRow(p, row, pos.StartLine+2+i, width)
	}
	return t
}

func (b *tableBuilder) parseRow(p buildState, row tableTrimmed, line int, width int) []*Text {
	out := make([]*Text, 0, width)
	pos := Position{StartLine: line, EndLine: line}
	start := 0
	unesc := nop
	for i := 0; i < len(row); i++ {
		c := row[i]
		if c == '\\' && i+1 < len(row) && row[i+1] == '|' {
			unesc = tableUnescape
			i++
			continue
		}
		if c == '|' {
			out = append(out, p.newText(pos, unesc(strings.Trim(string(row[start:i]), " \t\v\f"))))
			if len(out) == width {
				// Extra cells are discarded!
				return out
			}
			start = i + 1
			unesc = nop
		}
	}
	out = append(out, p.newText(pos, unesc(strings.Trim(string(row[start:]), " \t\v\f"))))
	for len(out) < width {
		// Missing cells are considered empty.
		out = append(out, p.newText(pos, ""))
	}
	return out
}

func nop(text string) string {
	return text
}

func tableUnescape(text string) string {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\\' && i+1 < len(text) && text[i+1] == '|' {
			i++
			c = '|'
		}
		out = append(out, c)
	}
	return string(out)
}

func (b *tableBuilder) parseAlign(delim tableTrimmed, n int) []string {
	align := make([]string, 0, tableCount(delim))
	start := 0
	for i := 0; i < len(delim); i++ {
		if delim[i] == '|' {
			align = append(align, tableAlign(string(delim[start:i])))
			start = i + 1
		}
	}
	align = append(align, tableAlign(string(delim[start:])))
	return align
}

func tableAlign(cell string) string {
	cell = tableTrimSpace(cell)
	l := cell[0] == ':'
	r := cell[len(cell)-1] == ':'
	switch {
	case l && r:
		return "center"
	case l:
		return "left"
	case r:
		return "right"
	}
	return ""
}

"""



```