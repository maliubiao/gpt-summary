Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Task:** The request asks for a functional summary of the provided Go code snippet, which is part of the `go/doc/comment` package. The goal is to understand what this code does in the context of Go documentation.

2. **High-Level Overview (Package and Purpose):** I see the `package comment` declaration. The comment at the beginning mentions parsing Go doc comments. This immediately tells me the code is about taking raw doc comment strings and turning them into a structured representation.

3. **Identify Key Data Structures:** I start looking for `struct` definitions. These are the building blocks of the parsed comment:
    * `Doc`:  The main container for a parsed comment. It holds `Content` (blocks) and `Links`.
    * `LinkDef`: Represents a link definition like `[text]: url`.
    * `Block`: An interface representing different types of content blocks (code, heading, list, paragraph).
    * Concrete block types: `Heading`, `List`, `ListItem`, `Paragraph`, `Code`. I examine the fields of each to understand what kind of information they store. For example, `List` has `Items`, `ForceBlankBefore`, and `ForceBlankBetween`, suggesting handling of list formatting.
    * `Text`: An interface for text-level elements within a block (plain text, italics, links, doc links).
    * Concrete text types: `Plain`, `Italic`, `Link`, `DocLink`. `DocLink`'s fields (`ImportPath`, `Recv`, `Name`) are crucial for understanding how code references are handled.
    * `Parser`: This struct holds configuration options for the parsing process, like `Words` for italicization/linking and `LookupPackage`/`LookupSym` for resolving documentation links.

4. **Identify Key Functions and Methods:**  I look for functions and methods, especially those related to parsing:
    * `Parser.Parse(text string) *Doc`: This is the main entry point for parsing. It takes raw comment text and returns a `Doc` struct.
    * `parseSpans(lines []string) []span`: This function seems to break down the comment into different kinds of "spans" (code blocks, headings, paragraphs, etc.).
    * Methods associated with block types (e.g., `d.list`, `d.code`, `d.paragraph`, `d.heading`, `d.oldHeading`): These are responsible for parsing specific types of blocks.
    * `parseLink(line string) (*LinkDef, bool)`: Parses a link definition.
    * `listMarker(line string) (num, rest string, ok bool)`:  Identifies list markers.
    * `parseLinkedText(text string) []Text`: Handles inline links within text.
    * `docLink(text, before, after string) (link *DocLink, ok bool)`: Specifically parses doc links (like `[fmt.Println]`).
    * `splitDocName(text string) (before, name string, foundDot bool)`: Helper for splitting doc link text.
    * `parseText(out []Text, s string, autoLink bool) []Text`: Parses plain text, potentially applying auto-linking based on `Parser.Words`.
    * Helper functions like `unindent`, `indented`, `isHeading`, `isList`, `autoURL`, `ident`, etc.: These support the main parsing logic.

5. **Infer Functionality by Connecting Structures and Functions:** I start connecting the dots:
    * The `Parser` uses its configuration (`Words`, `LookupPackage`, `LookupSym`) to guide the parsing process.
    * `parseSpans` identifies the high-level structure.
    * The specific parsing methods for each block type (`d.list`, etc.) create the corresponding `Block` structs.
    * `parseLinkedText` and `docLink` handle different kinds of links, creating `Link` and `DocLink` structs.
    * The `Doc` struct aggregates all the parsed information.

6. **Formulate a Concise Summary:** Based on the above analysis, I condense the functionality into a few key points:
    * Parsing Go doc comments into a structured representation.
    * Identifying and representing different block-level elements (code, headings, lists, paragraphs).
    * Recognizing and storing link definitions.
    * Handling inline links (both regular URLs and Go documentation links).
    * Providing a `Parser` struct for customization.

7. **Review and Refine:** I read through my summary to ensure it's accurate, clear, and covers the main functionalities exposed by the code. I check if I missed any major components or interactions. For instance, I noticed the `ForceBlankBefore` and `ForceBlankBetween` fields in `List`, highlighting the code's attention to formatting nuances.

Essentially, I'm doing a form of reverse engineering: starting with the code and inferring its purpose and how it achieves it by examining its structure, data types, and functions. The comments within the code are helpful hints, but the core understanding comes from analyzing the code itself. The request specifically asked for a summary of *its* functions, so I focused on what this *specific* code segment does, rather than the broader functionality of the `go/doc` package.


这段代码是 Go 语言 `go/doc/comment` 包中 `parse.go` 文件的一部分，它的主要功能是 **解析 Go 语言的文档注释 (doc comments)**。

更具体地说，这段代码实现了将一段 Go 语言的文档注释字符串解析成一个结构化的 `Doc` 对象的过程。这个 `Doc` 对象包含了注释中的各种元素，例如段落、标题、代码块、列表以及链接。

**归纳一下它的功能：**

1. **将 Go 文档注释文本分解成不同的内容块 (Blocks):**  能够识别和区分段落、标题、代码块和列表等不同类型的结构化内容。
2. **解析链接定义 (Link Definitions):**  可以提取出形如 `[text]: url` 的链接定义，并存储在 `Links` 字段中。
3. **解析内联链接 (Inline Links):**  能够识别并解析注释文本中的内联链接，例如 `[math.Sin]` (文档链接) 和 `[Go home page](https://go.dev)` (普通链接)。
4. **处理文本格式 (Text Formatting):**  可以识别并表示文本中的斜体。
5. **提供可配置的解析器 (Parser):**  `Parser` 结构体允许用户自定义解析行为，例如指定哪些标识符应该被斜体化或链接，以及如何查找包和符号的文档。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码是 Go 语言工具链中用于处理文档注释的核心部分。它被用于将 Go 源代码中的文档注释转换成结构化的数据，以便于生成各种形式的文档，例如 godoc 生成的 HTML 文档。

**Go 代码举例说明:**

假设我们有以下 Go 代码和文档注释：

```go
package mypkg

// Add returns the sum of two integers.
//
// Example usage:
//  result := Add(1, 2) // result will be 3
//
// See also: [fmt.Println].
//
// For more details, visit the [Go home page](https://go.dev).
func Add(a, b int) int {
	return a + b
}
```

使用 `comment.Parser` 解析这段注释，假设 `LookupSym` 和 `LookupPackage` 能够正确解析 `fmt.Println` 和 `fmt`。

**假设的输入：**

```
Add returns the sum of two integers.

Example usage:
 result := Add(1, 2) // result will be 3

See also: [fmt.Println].

For more details, visit the [Go home page](https://go.dev).
```

**可能的输出 (简化的 `Doc` 结构体表示):**

```
Doc{
    Content: []Block{
        &Paragraph{Text: []Text{Plain("Add returns the sum of two integers.")}},
        &Paragraph{Text: []Text{Plain("Example usage:")}},
        &Code{Text: " result := Add(1, 2) // result will be 3\n"},
        &Paragraph{Text: []Text{Plain("See also: "), &DocLink{ImportPath: "fmt", Name: "Println"}}},
        &Paragraph{Text: []Text{Plain("For more details, visit the "), &Link{Text: []Text{Plain("Go home page")}, URL: "https://go.dev"}}},
    },
    Links: []*LinkDef{
        {Text: "Go home page", URL: "https://go.dev", Used: true},
    },
}
```

**涉及代码推理，需要带上假设的输入与输出:**

上面的例子已经包含了代码推理和假设的输入输出。代码会根据文档注释的语法规则，将文本解析成不同的 `Block` 和 `Text` 类型。例如，以缩进开头的行会被识别为 `Code` 块，而 `[...](...)` 形式的文本会被解析为 `Link`。

**没有涉及命令行参数的具体处理，因此无需介绍。**

**总结其功能：**

这段 `parse.go` 代码的核心功能是 **将 Go 语言的文档注释字符串转换成一个结构化的、易于程序处理的 `Doc` 对象**。它能够识别和解析注释中的各种元素，包括文本段落、标题、代码块、列表以及各种类型的链接，为后续的文档生成和处理提供基础数据。

Prompt: 
```
这是路径为go/src/go/doc/comment/parse.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package comment

import (
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A Doc is a parsed Go doc comment.
type Doc struct {
	// Content is the sequence of content blocks in the comment.
	Content []Block

	// Links is the link definitions in the comment.
	Links []*LinkDef
}

// A LinkDef is a single link definition.
type LinkDef struct {
	Text string // the link text
	URL  string // the link URL
	Used bool   // whether the comment uses the definition
}

// A Block is block-level content in a doc comment,
// one of [*Code], [*Heading], [*List], or [*Paragraph].
type Block interface {
	block()
}

// A Heading is a doc comment heading.
type Heading struct {
	Text []Text // the heading text
}

func (*Heading) block() {}

// A List is a numbered or bullet list.
// Lists are always non-empty: len(Items) > 0.
// In a numbered list, every Items[i].Number is a non-empty string.
// In a bullet list, every Items[i].Number is an empty string.
type List struct {
	// Items is the list items.
	Items []*ListItem

	// ForceBlankBefore indicates that the list must be
	// preceded by a blank line when reformatting the comment,
	// overriding the usual conditions. See the BlankBefore method.
	//
	// The comment parser sets ForceBlankBefore for any list
	// that is preceded by a blank line, to make sure
	// the blank line is preserved when printing.
	ForceBlankBefore bool

	// ForceBlankBetween indicates that list items must be
	// separated by blank lines when reformatting the comment,
	// overriding the usual conditions. See the BlankBetween method.
	//
	// The comment parser sets ForceBlankBetween for any list
	// that has a blank line between any two of its items, to make sure
	// the blank lines are preserved when printing.
	ForceBlankBetween bool
}

func (*List) block() {}

// BlankBefore reports whether a reformatting of the comment
// should include a blank line before the list.
// The default rule is the same as for [BlankBetween]:
// if the list item content contains any blank lines
// (meaning at least one item has multiple paragraphs)
// then the list itself must be preceded by a blank line.
// A preceding blank line can be forced by setting [List].ForceBlankBefore.
func (l *List) BlankBefore() bool {
	return l.ForceBlankBefore || l.BlankBetween()
}

// BlankBetween reports whether a reformatting of the comment
// should include a blank line between each pair of list items.
// The default rule is that if the list item content contains any blank lines
// (meaning at least one item has multiple paragraphs)
// then list items must themselves be separated by blank lines.
// Blank line separators can be forced by setting [List].ForceBlankBetween.
func (l *List) BlankBetween() bool {
	if l.ForceBlankBetween {
		return true
	}
	for _, item := range l.Items {
		if len(item.Content) != 1 {
			// Unreachable for parsed comments today,
			// since the only way to get multiple item.Content
			// is multiple paragraphs, which must have been
			// separated by a blank line.
			return true
		}
	}
	return false
}

// A ListItem is a single item in a numbered or bullet list.
type ListItem struct {
	// Number is a decimal string in a numbered list
	// or an empty string in a bullet list.
	Number string // "1", "2", ...; "" for bullet list

	// Content is the list content.
	// Currently, restrictions in the parser and printer
	// require every element of Content to be a *Paragraph.
	Content []Block // Content of this item.
}

// A Paragraph is a paragraph of text.
type Paragraph struct {
	Text []Text
}

func (*Paragraph) block() {}

// A Code is a preformatted code block.
type Code struct {
	// Text is the preformatted text, ending with a newline character.
	// It may be multiple lines, each of which ends with a newline character.
	// It is never empty, nor does it start or end with a blank line.
	Text string
}

func (*Code) block() {}

// A Text is text-level content in a doc comment,
// one of [Plain], [Italic], [*Link], or [*DocLink].
type Text interface {
	text()
}

// A Plain is a string rendered as plain text (not italicized).
type Plain string

func (Plain) text() {}

// An Italic is a string rendered as italicized text.
type Italic string

func (Italic) text() {}

// A Link is a link to a specific URL.
type Link struct {
	Auto bool   // is this an automatic (implicit) link of a literal URL?
	Text []Text // text of link
	URL  string // target URL of link
}

func (*Link) text() {}

// A DocLink is a link to documentation for a Go package or symbol.
type DocLink struct {
	Text []Text // text of link

	// ImportPath, Recv, and Name identify the Go package or symbol
	// that is the link target. The potential combinations of
	// non-empty fields are:
	//  - ImportPath: a link to another package
	//  - ImportPath, Name: a link to a const, func, type, or var in another package
	//  - ImportPath, Recv, Name: a link to a method in another package
	//  - Name: a link to a const, func, type, or var in this package
	//  - Recv, Name: a link to a method in this package
	ImportPath string // import path
	Recv       string // receiver type, without any pointer star, for methods
	Name       string // const, func, type, var, or method name
}

func (*DocLink) text() {}

// A Parser is a doc comment parser.
// The fields in the struct can be filled in before calling [Parser.Parse]
// in order to customize the details of the parsing process.
type Parser struct {
	// Words is a map of Go identifier words that
	// should be italicized and potentially linked.
	// If Words[w] is the empty string, then the word w
	// is only italicized. Otherwise it is linked, using
	// Words[w] as the link target.
	// Words corresponds to the [go/doc.ToHTML] words parameter.
	Words map[string]string

	// LookupPackage resolves a package name to an import path.
	//
	// If LookupPackage(name) returns ok == true, then [name]
	// (or [name.Sym] or [name.Sym.Method])
	// is considered a documentation link to importPath's package docs.
	// It is valid to return "", true, in which case name is considered
	// to refer to the current package.
	//
	// If LookupPackage(name) returns ok == false,
	// then [name] (or [name.Sym] or [name.Sym.Method])
	// will not be considered a documentation link,
	// except in the case where name is the full (but single-element) import path
	// of a package in the standard library, such as in [math] or [io.Reader].
	// LookupPackage is still called for such names,
	// in order to permit references to imports of other packages
	// with the same package names.
	//
	// Setting LookupPackage to nil is equivalent to setting it to
	// a function that always returns "", false.
	LookupPackage func(name string) (importPath string, ok bool)

	// LookupSym reports whether a symbol name or method name
	// exists in the current package.
	//
	// If LookupSym("", "Name") returns true, then [Name]
	// is considered a documentation link for a const, func, type, or var.
	//
	// Similarly, if LookupSym("Recv", "Name") returns true,
	// then [Recv.Name] is considered a documentation link for
	// type Recv's method Name.
	//
	// Setting LookupSym to nil is equivalent to setting it to a function
	// that always returns false.
	LookupSym func(recv, name string) (ok bool)
}

// parseDoc is parsing state for a single doc comment.
type parseDoc struct {
	*Parser
	*Doc
	links     map[string]*LinkDef
	lines     []string
	lookupSym func(recv, name string) bool
}

// lookupPkg is called to look up the pkg in [pkg], [pkg.Name], and [pkg.Name.Recv].
// If pkg has a slash, it is assumed to be the full import path and is returned with ok = true.
//
// Otherwise, pkg is probably a simple package name like "rand" (not "crypto/rand" or "math/rand").
// d.LookupPackage provides a way for the caller to allow resolving such names with reference
// to the imports in the surrounding package.
//
// There is one collision between these two cases: single-element standard library names
// like "math" are full import paths but don't contain slashes. We let d.LookupPackage have
// the first chance to resolve it, in case there's a different package imported as math,
// and otherwise we refer to a built-in list of single-element standard library package names.
func (d *parseDoc) lookupPkg(pkg string) (importPath string, ok bool) {
	if strings.Contains(pkg, "/") { // assume a full import path
		if validImportPath(pkg) {
			return pkg, true
		}
		return "", false
	}
	if d.LookupPackage != nil {
		// Give LookupPackage a chance.
		if path, ok := d.LookupPackage(pkg); ok {
			return path, true
		}
	}
	return DefaultLookupPackage(pkg)
}

func isStdPkg(path string) bool {
	_, ok := slices.BinarySearch(stdPkgs, path)
	return ok
}

// DefaultLookupPackage is the default package lookup
// function, used when [Parser.LookupPackage] is nil.
// It recognizes names of the packages from the standard
// library with single-element import paths, such as math,
// which would otherwise be impossible to name.
//
// Note that the go/doc package provides a more sophisticated
// lookup based on the imports used in the current package.
func DefaultLookupPackage(name string) (importPath string, ok bool) {
	if isStdPkg(name) {
		return name, true
	}
	return "", false
}

// Parse parses the doc comment text and returns the *[Doc] form.
// Comment markers (/* // and */) in the text must have already been removed.
func (p *Parser) Parse(text string) *Doc {
	lines := unindent(strings.Split(text, "\n"))
	d := &parseDoc{
		Parser:    p,
		Doc:       new(Doc),
		links:     make(map[string]*LinkDef),
		lines:     lines,
		lookupSym: func(recv, name string) bool { return false },
	}
	if p.LookupSym != nil {
		d.lookupSym = p.LookupSym
	}

	// First pass: break into block structure and collect known links.
	// The text is all recorded as Plain for now.
	var prev span
	for _, s := range parseSpans(lines) {
		var b Block
		switch s.kind {
		default:
			panic("go/doc/comment: internal error: unknown span kind")
		case spanList:
			b = d.list(lines[s.start:s.end], prev.end < s.start)
		case spanCode:
			b = d.code(lines[s.start:s.end])
		case spanOldHeading:
			b = d.oldHeading(lines[s.start])
		case spanHeading:
			b = d.heading(lines[s.start])
		case spanPara:
			b = d.paragraph(lines[s.start:s.end])
		}
		if b != nil {
			d.Content = append(d.Content, b)
		}
		prev = s
	}

	// Second pass: interpret all the Plain text now that we know the links.
	for _, b := range d.Content {
		switch b := b.(type) {
		case *Paragraph:
			b.Text = d.parseLinkedText(string(b.Text[0].(Plain)))
		case *List:
			for _, i := range b.Items {
				for _, c := range i.Content {
					p := c.(*Paragraph)
					p.Text = d.parseLinkedText(string(p.Text[0].(Plain)))
				}
			}
		}
	}

	return d.Doc
}

// A span represents a single span of comment lines (lines[start:end])
// of an identified kind (code, heading, paragraph, and so on).
type span struct {
	start int
	end   int
	kind  spanKind
}

// A spanKind describes the kind of span.
type spanKind int

const (
	_ spanKind = iota
	spanCode
	spanHeading
	spanList
	spanOldHeading
	spanPara
)

func parseSpans(lines []string) []span {
	var spans []span

	// The loop may process a line twice: once as unindented
	// and again forced indented. So the maximum expected
	// number of iterations is 2*len(lines). The repeating logic
	// can be subtle, though, and to protect against introduction
	// of infinite loops in future changes, we watch to see that
	// we are not looping too much. A panic is better than a
	// quiet infinite loop.
	watchdog := 2 * len(lines)

	i := 0
	forceIndent := 0
Spans:
	for {
		// Skip blank lines.
		for i < len(lines) && lines[i] == "" {
			i++
		}
		if i >= len(lines) {
			break
		}
		if watchdog--; watchdog < 0 {
			panic("go/doc/comment: internal error: not making progress")
		}

		var kind spanKind
		start := i
		end := i
		if i < forceIndent || indented(lines[i]) {
			// Indented (or force indented).
			// Ends before next unindented. (Blank lines are OK.)
			// If this is an unindented list that we are heuristically treating as indented,
			// then accept unindented list item lines up to the first blank lines.
			// The heuristic is disabled at blank lines to contain its effect
			// to non-gofmt'ed sections of the comment.
			unindentedListOK := isList(lines[i]) && i < forceIndent
			i++
			for i < len(lines) && (lines[i] == "" || i < forceIndent || indented(lines[i]) || (unindentedListOK && isList(lines[i]))) {
				if lines[i] == "" {
					unindentedListOK = false
				}
				i++
			}

			// Drop trailing blank lines.
			end = i
			for end > start && lines[end-1] == "" {
				end--
			}

			// If indented lines are followed (without a blank line)
			// by an unindented line ending in a brace,
			// take that one line too. This fixes the common mistake
			// of pasting in something like
			//
			// func main() {
			//	fmt.Println("hello, world")
			// }
			//
			// and forgetting to indent it.
			// The heuristic will never trigger on a gofmt'ed comment,
			// because any gofmt'ed code block or list would be
			// followed by a blank line or end of comment.
			if end < len(lines) && strings.HasPrefix(lines[end], "}") {
				end++
			}

			if isList(lines[start]) {
				kind = spanList
			} else {
				kind = spanCode
			}
		} else {
			// Unindented. Ends at next blank or indented line.
			i++
			for i < len(lines) && lines[i] != "" && !indented(lines[i]) {
				i++
			}
			end = i

			// If unindented lines are followed (without a blank line)
			// by an indented line that would start a code block,
			// check whether the final unindented lines
			// should be left for the indented section.
			// This can happen for the common mistakes of
			// unindented code or unindented lists.
			// The heuristic will never trigger on a gofmt'ed comment,
			// because any gofmt'ed code block would have a blank line
			// preceding it after the unindented lines.
			if i < len(lines) && lines[i] != "" && !isList(lines[i]) {
				switch {
				case isList(lines[i-1]):
					// If the final unindented line looks like a list item,
					// this may be the first indented line wrap of
					// a mistakenly unindented list.
					// Leave all the unindented list items.
					forceIndent = end
					end--
					for end > start && isList(lines[end-1]) {
						end--
					}

				case strings.HasSuffix(lines[i-1], "{") || strings.HasSuffix(lines[i-1], `\`):
					// If the final unindented line ended in { or \
					// it is probably the start of a misindented code block.
					// Give the user a single line fix.
					// Often that's enough; if not, the user can fix the others themselves.
					forceIndent = end
					end--
				}

				if start == end && forceIndent > start {
					i = start
					continue Spans
				}
			}

			// Span is either paragraph or heading.
			if end-start == 1 && isHeading(lines[start]) {
				kind = spanHeading
			} else if end-start == 1 && isOldHeading(lines[start], lines, start) {
				kind = spanOldHeading
			} else {
				kind = spanPara
			}
		}

		spans = append(spans, span{start, end, kind})
		i = end
	}

	return spans
}

// indented reports whether line is indented
// (starts with a leading space or tab).
func indented(line string) bool {
	return line != "" && (line[0] == ' ' || line[0] == '\t')
}

// unindent removes any common space/tab prefix
// from each line in lines, returning a copy of lines in which
// those prefixes have been trimmed from each line.
// It also replaces any lines containing only spaces with blank lines (empty strings).
func unindent(lines []string) []string {
	// Trim leading and trailing blank lines.
	for len(lines) > 0 && isBlank(lines[0]) {
		lines = lines[1:]
	}
	for len(lines) > 0 && isBlank(lines[len(lines)-1]) {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return nil
	}

	// Compute and remove common indentation.
	prefix := leadingSpace(lines[0])
	for _, line := range lines[1:] {
		if !isBlank(line) {
			prefix = commonPrefix(prefix, leadingSpace(line))
		}
	}

	out := make([]string, len(lines))
	for i, line := range lines {
		line = strings.TrimPrefix(line, prefix)
		if strings.TrimSpace(line) == "" {
			line = ""
		}
		out[i] = line
	}
	for len(out) > 0 && out[0] == "" {
		out = out[1:]
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return out
}

// isBlank reports whether s is a blank line.
func isBlank(s string) bool {
	return len(s) == 0 || (len(s) == 1 && s[0] == '\n')
}

// commonPrefix returns the longest common prefix of a and b.
func commonPrefix(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return a[0:i]
}

// leadingSpace returns the longest prefix of s consisting of spaces and tabs.
func leadingSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return s[:i]
}

// isOldHeading reports whether line is an old-style section heading.
// line is all[off].
func isOldHeading(line string, all []string, off int) bool {
	if off <= 0 || all[off-1] != "" || off+2 >= len(all) || all[off+1] != "" || leadingSpace(all[off+2]) != "" {
		return false
	}

	line = strings.TrimSpace(line)

	// a heading must start with an uppercase letter
	r, _ := utf8.DecodeRuneInString(line)
	if !unicode.IsLetter(r) || !unicode.IsUpper(r) {
		return false
	}

	// it must end in a letter or digit:
	r, _ = utf8.DecodeLastRuneInString(line)
	if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
		return false
	}

	// exclude lines with illegal characters. we allow "(),"
	if strings.ContainsAny(line, ";:!?+*/=[]{}_^°&§~%#@<\">\\") {
		return false
	}

	// allow "'" for possessive "'s" only
	for b := line; ; {
		var ok bool
		if _, b, ok = strings.Cut(b, "'"); !ok {
			break
		}
		if b != "s" && !strings.HasPrefix(b, "s ") {
			return false // ' not followed by s and then end-of-word
		}
	}

	// allow "." when followed by non-space
	for b := line; ; {
		var ok bool
		if _, b, ok = strings.Cut(b, "."); !ok {
			break
		}
		if b == "" || strings.HasPrefix(b, " ") {
			return false // not followed by non-space
		}
	}

	return true
}

// oldHeading returns the *Heading for the given old-style section heading line.
func (d *parseDoc) oldHeading(line string) Block {
	return &Heading{Text: []Text{Plain(strings.TrimSpace(line))}}
}

// isHeading reports whether line is a new-style section heading.
func isHeading(line string) bool {
	return len(line) >= 2 &&
		line[0] == '#' &&
		(line[1] == ' ' || line[1] == '\t') &&
		strings.TrimSpace(line) != "#"
}

// heading returns the *Heading for the given new-style section heading line.
func (d *parseDoc) heading(line string) Block {
	return &Heading{Text: []Text{Plain(strings.TrimSpace(line[1:]))}}
}

// code returns a code block built from the lines.
func (d *parseDoc) code(lines []string) *Code {
	body := unindent(lines)
	body = append(body, "") // to get final \n from Join
	return &Code{Text: strings.Join(body, "\n")}
}

// paragraph returns a paragraph block built from the lines.
// If the lines are link definitions, paragraph adds them to d and returns nil.
func (d *parseDoc) paragraph(lines []string) Block {
	// Is this a block of known links? Handle.
	var defs []*LinkDef
	for _, line := range lines {
		def, ok := parseLink(line)
		if !ok {
			goto NoDefs
		}
		defs = append(defs, def)
	}
	for _, def := range defs {
		d.Links = append(d.Links, def)
		if d.links[def.Text] == nil {
			d.links[def.Text] = def
		}
	}
	return nil
NoDefs:

	return &Paragraph{Text: []Text{Plain(strings.Join(lines, "\n"))}}
}

// parseLink parses a single link definition line:
//
//	[text]: url
//
// It returns the link definition and whether the line was well formed.
func parseLink(line string) (*LinkDef, bool) {
	if line == "" || line[0] != '[' {
		return nil, false
	}
	i := strings.Index(line, "]:")
	if i < 0 || i+3 >= len(line) || (line[i+2] != ' ' && line[i+2] != '\t') {
		return nil, false
	}

	text := line[1:i]
	url := strings.TrimSpace(line[i+3:])
	j := strings.Index(url, "://")
	if j < 0 || !isScheme(url[:j]) {
		return nil, false
	}

	// Line has right form and has valid scheme://.
	// That's good enough for us - we are not as picky
	// about the characters beyond the :// as we are
	// when extracting inline URLs from text.
	return &LinkDef{Text: text, URL: url}, true
}

// list returns a list built from the indented lines,
// using forceBlankBefore as the value of the List's ForceBlankBefore field.
func (d *parseDoc) list(lines []string, forceBlankBefore bool) *List {
	num, _, _ := listMarker(lines[0])
	var (
		list *List = &List{ForceBlankBefore: forceBlankBefore}
		item *ListItem
		text []string
	)
	flush := func() {
		if item != nil {
			if para := d.paragraph(text); para != nil {
				item.Content = append(item.Content, para)
			}
		}
		text = nil
	}

	for _, line := range lines {
		if n, after, ok := listMarker(line); ok && (n != "") == (num != "") {
			// start new list item
			flush()

			item = &ListItem{Number: n}
			list.Items = append(list.Items, item)
			line = after
		}
		line = strings.TrimSpace(line)
		if line == "" {
			list.ForceBlankBetween = true
			flush()
			continue
		}
		text = append(text, strings.TrimSpace(line))
	}
	flush()
	return list
}

// listMarker parses the line as beginning with a list marker.
// If it can do that, it returns the numeric marker ("" for a bullet list),
// the rest of the line, and ok == true.
// Otherwise, it returns "", "", false.
func listMarker(line string) (num, rest string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}

	// Can we find a marker?
	if r, n := utf8.DecodeRuneInString(line); r == '•' || r == '*' || r == '+' || r == '-' {
		num, rest = "", line[n:]
	} else if '0' <= line[0] && line[0] <= '9' {
		n := 1
		for n < len(line) && '0' <= line[n] && line[n] <= '9' {
			n++
		}
		if n >= len(line) || (line[n] != '.' && line[n] != ')') {
			return "", "", false
		}
		num, rest = line[:n], line[n+1:]
	} else {
		return "", "", false
	}

	if !indented(rest) || strings.TrimSpace(rest) == "" {
		return "", "", false
	}

	return num, rest, true
}

// isList reports whether the line is the first line of a list,
// meaning starts with a list marker after any indentation.
// (The caller is responsible for checking the line is indented, as appropriate.)
func isList(line string) bool {
	_, _, ok := listMarker(line)
	return ok
}

// parseLinkedText parses text that is allowed to contain explicit links,
// such as [math.Sin] or [Go home page], into a slice of Text items.
//
// A “pkg” is only assumed to be a full import path if it starts with
// a domain name (a path element with a dot) or is one of the packages
// from the standard library (“[os]”, “[encoding/json]”, and so on).
// To avoid problems with maps, generics, and array types, doc links
// must be both preceded and followed by punctuation, spaces, tabs,
// or the start or end of a line. An example problem would be treating
// map[ast.Expr]TypeAndValue as containing a link.
func (d *parseDoc) parseLinkedText(text string) []Text {
	var out []Text
	wrote := 0
	flush := func(i int) {
		if wrote < i {
			out = d.parseText(out, text[wrote:i], true)
			wrote = i
		}
	}

	start := -1
	var buf []byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\n' || c == '\t' {
			c = ' '
		}
		switch c {
		case '[':
			start = i
		case ']':
			if start >= 0 {
				if def, ok := d.links[string(buf)]; ok {
					def.Used = true
					flush(start)
					out = append(out, &Link{
						Text: d.parseText(nil, text[start+1:i], false),
						URL:  def.URL,
					})
					wrote = i + 1
				} else if link, ok := d.docLink(text[start+1:i], text[:start], text[i+1:]); ok {
					flush(start)
					link.Text = d.parseText(nil, text[start+1:i], false)
					out = append(out, link)
					wrote = i + 1
				}
			}
			start = -1
			buf = buf[:0]
		}
		if start >= 0 && i != start {
			buf = append(buf, c)
		}
	}

	flush(len(text))
	return out
}

// docLink parses text, which was found inside [ ] brackets,
// as a doc link if possible, returning the DocLink and ok == true
// or else nil, false.
// The before and after strings are the text before the [ and after the ]
// on the same line. Doc links must be preceded and followed by
// punctuation, spaces, tabs, or the start or end of a line.
func (d *parseDoc) docLink(text, before, after string) (link *DocLink, ok bool) {
	if before != "" {
		r, _ := utf8.DecodeLastRuneInString(before)
		if !unicode.IsPunct(r) && r != ' ' && r != '\t' && r != '\n' {
			return nil, false
		}
	}
	if after != "" {
		r, _ := utf8.DecodeRuneInString(after)
		if !unicode.IsPunct(r) && r != ' ' && r != '\t' && r != '\n' {
			return nil, false
		}
	}
	text = strings.TrimPrefix(text, "*")
	pkg, name, ok := splitDocName(text)
	var recv string
	if ok {
		pkg, recv, _ = splitDocName(pkg)
	}
	if pkg != "" {
		if pkg, ok = d.lookupPkg(pkg); !ok {
			return nil, false
		}
	} else {
		if ok = d.lookupSym(recv, name); !ok {
			return nil, false
		}
	}
	link = &DocLink{
		ImportPath: pkg,
		Recv:       recv,
		Name:       name,
	}
	return link, true
}

// If text is of the form before.Name, where Name is a capitalized Go identifier,
// then splitDocName returns before, name, true.
// Otherwise it returns text, "", false.
func splitDocName(text string) (before, name string, foundDot bool) {
	i := strings.LastIndex(text, ".")
	name = text[i+1:]
	if !isName(name) {
		return text, "", false
	}
	if i >= 0 {
		before = text[:i]
	}
	return before, name, true
}

// parseText parses s as text and returns the result of appending
// those parsed Text elements to out.
// parseText does not handle explicit links like [math.Sin] or [Go home page]:
// those are handled by parseLinkedText.
// If autoLink is true, then parseText recognizes URLs and words from d.Words
// and converts those to links as appropriate.
func (d *parseDoc) parseText(out []Text, s string, autoLink bool) []Text {
	var w strings.Builder
	wrote := 0
	writeUntil := func(i int) {
		w.WriteString(s[wrote:i])
		wrote = i
	}
	flush := func(i int) {
		writeUntil(i)
		if w.Len() > 0 {
			out = append(out, Plain(w.String()))
			w.Reset()
		}
	}
	for i := 0; i < len(s); {
		t := s[i:]
		if autoLink {
			if url, ok := autoURL(t); ok {
				flush(i)
				// Note: The old comment parser would look up the URL in words
				// and replace the target with words[URL] if it was non-empty.
				// That would allow creating links that display as one URL but
				// when clicked go to a different URL. Not sure what the point
				// of that is, so we're not doing that lookup here.
				out = append(out, &Link{Auto: true, Text: []Text{Plain(url)}, URL: url})
				i += len(url)
				wrote = i
				continue
			}
			if id, ok := ident(t); ok {
				url, italics := d.Words[id]
				if !italics {
					i += len(id)
					continue
				}
				flush(i)
				if url == "" {
					out = append(out, Italic(id))
				} else {
					out = append(out, &Link{Auto: true, Text: []Text{Italic(id)}, URL: url})
				}
				i += len(id)
				wrote = i
				continue
			}
		}
		switch {
		case strings.HasPrefix(t, "``"):
			if len(t) >= 3 && t[2] == '`' {
				// Do not convert `` inside ```, in case people are mistakenly writing Markdown.
				i += 3
				for i < len(t) && t[i] == '`' {
					i++
				}
				break
			}
			writeUntil(i)
			w.WriteRune('“')
			i += 2
			wrote = i
		case strings.HasPrefix(t, "''"):
			writeUntil(i)
			w.WriteRune('”')
			i += 2
			wrote = i
		default:
			i++
		}
	}
	flush(len(s))
	return out
}

// autoURL checks whether s begins with a URL that should be hyperlinked.
// If so, it returns the URL, which is a prefix of s, and ok == true.
// Otherwise it returns "", false.
// The caller should skip over the first len(url) bytes of s
// before further processing.
func autoURL(s string) (url string, ok bool) {
	// Find the ://. Fast path to pick off non-URL,
	// since we call this at every position in the string.
	// The shortest possible URL is ftp://x, 7 bytes.
	var i int
	switch {
	case len(s) < 7:
		return "", false
	case s[3] == ':':
		i = 3
	case s[4] == ':':
		i = 4
	case s[5] == ':':
		i = 5
	case s[6] == ':':
		i = 6
	default:
		return "", false
	}
	if i+3 > len(s) || s[i:i+3] != "://" {
		return "", false
	}

	// Check valid scheme.
	if !isScheme(s[:i]) {
		return "", false
	}

	// Scan host part. Must have at least one byte,
	// and must start and end in non-punctuation.
	i += 3
	if i >= len(s) || !isHost(s[i]) || isPunct(s[i]) {
		return "", false
	}
	i++
	end := i
	for i < len(s) && isHost(s[i]) {
		if !isPunct(s[i]) {
			end = i + 1
		}
		i++
	}
	i = end

	// At this point we are definitely returning a URL (scheme://host).
	// We just have to find the longest path we can add to it.
	// Heuristics abound.
	// We allow parens, braces, and brackets,
	// but only if they match (#5043, #22285).
	// We allow .,:;?! in the path but not at the end,
	// to avoid end-of-sentence punctuation (#18139, #16565).
	stk := []byte{}
	end = i
Path:
	for ; i < len(s); i++ {
		if isPunct(s[i]) {
			continue
		}
		if !isPath(s[i]) {
			break
		}
		switch s[i] {
		case '(':
			stk = append(stk, ')')
		case '{':
			stk = append(stk, '}')
		case '[':
			stk = append(stk, ']')
		case ')', '}', ']':
			if len(stk) == 0 || stk[len(stk)-1] != s[i] {
				break Path
			}
			stk = stk[:len(stk)-1]
		}
		if len(stk) == 0 {
			end = i + 1
		}
	}

	return s[:end], true
}

// isScheme reports whether s is a recognized URL scheme.
// Note that if strings of new length (beyond 3-7)
// are added here, the fast path at the top of autoURL will need updating.
func isScheme(s string) bool {
	switch s {
	case "file",
		"ftp",
		"gopher",
		"http",
		"https",
		"mailto",
		"nntp":
		return true
	}
	return false
}

// isHost reports whether c is a byte that can appear in a URL host,
// like www.example.com or user@[::1]:8080
func isHost(c byte) bool {
	// mask is a 128-bit bitmap with 1s for allowed bytes,
	// so that the byte c can be tested with a shift and an and.
	// If c > 128, then 1<<c and 1<<(c-64) will both be zero,
	// and this function will return false.
	const mask = 0 |
		(1<<26-1)<<'A' |
		(1<<26-1)<<'a' |
		(1<<10-1)<<'0' |
		1<<'_' |
		1<<'@' |
		1<<'-' |
		1<<'.' |
		1<<'[' |
		1<<']' |
		1<<':'

	return ((uint64(1)<<c)&(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&(mask>>64)) != 0
}

// isPunct reports whether c is a punctuation byte that can appear
// inside a path but not at the end.
func isPunct(c byte) bool {
	// mask is a 128-bit bitmap with 1s for allowed bytes,
	// so that the byte c can be tested with a shift and an and.
	// If c > 128, then 1<<c and 1<<(c-64) will both be zero,
	// and this function will return false.
	const mask = 0 |
		1<<'.' |
		1<<',' |
		1<<':' |
		1<<';' |
		1<<'?' |
		1<<'!'

	return ((uint64(1)<<c)&(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&(mask>>64)) != 0
}

// isPath reports whether c is a (non-punctuation) path byte.
func isPath(c byte) bool {
	// mask is a 128-bit bitmap with 1s for allowed bytes,
	// so that the byte c can be tested with a shift and an and.
	// If c > 128, then 1<<c and 1<<(c-64) will both be zero,
	// and this function will return false.
	const mask = 0 |
		(1<<26-1)<<'A' |
		(1<<26-1)<<'a' |
		(1<<10-1)<<'0' |
		1<<'$' |
		1<<'\'' |
		1<<'(' |
		1<<')' |
		1<<'*' |
		1<<'+' |
		1<<'&' |
		1<<'#' |
		1<<'=' |
		1<<'@' |
		1<<'~' |
		1<<'_' |
		1<<'/' |
		1<<'-' |
		1<<'[' |
		1<<']' |
		1<<'{' |
		1<<'}' |
		1<<'%'

	return ((uint64(1)<<c)&(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&(mask>>64)) != 0
}

// isName reports whether s is a capitalized Go identifier (like Name).
func isName(s string) bool {
	t, ok := ident(s)
	if !ok || t != s {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s)
	return unicode.IsUpper(r)
}

// ident checks whether s begins with a Go identifier.
// If so, it returns the identifier, which is a prefix of s, and ok == true.
// Otherwise it returns "", false.
// The caller should skip over the first len(id) bytes of s
// before further processing.
func ident(s string) (id string, ok bool) {
	// Scan [\pL_][\pL_0-9]*
	n := 0
	for n < len(s) {
		if c := s[n]; c < utf8.RuneSelf {
			if isIdentASCII(c) && (n > 0 || c < '0' || c > '9') {
				n++
				continue
			}
			break
		}
		r, nr := utf8.DecodeRuneInString(s[n:])
		if unicode.IsLetter(r) {
			n += nr
			continue
		}
		break
	}
	return s[:n], n > 0
}

// isIdentASCII reports whether c is an ASCII identifier byte.
func isIdentASCII(c byte) bool {
	// mask is a 128-bit bitmap with 1s for allowed bytes,
	// so that the byte c can be tested with a shift and an and.
	// If c > 128
"""




```