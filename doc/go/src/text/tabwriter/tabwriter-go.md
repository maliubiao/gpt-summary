Response:
Let's break down the thought process for analyzing the `tabwriter.go` code and generating the desired output.

**1. Understanding the Core Functionality:**

The first step is to read the package documentation and the code comments. The key phrases that immediately jump out are:

* "translates tabbed columns in input into properly aligned text"
* "Elastic Tabstops algorithm"
* "write filter"
* "padding around tab-delimited columns"
* "align the columns"

These tell us the central purpose: taking text with tabs and making the columns line up nicely. The mention of "Elastic Tabstops" hints at a more sophisticated alignment than simple fixed-width tabs.

**2. Identifying Key Components:**

Next, I'd scan the `Writer` struct and its methods. This helps understand the internal workings:

* `output io.Writer`: Where the formatted output goes.
* `minwidth`, `tabwidth`, `padding`, `padchar`, `flags`: Configuration options for the alignment.
* `buf []byte`:  A buffer to hold the input text.
* `lines [][]cell`:  The core data structure representing the input lines and their cells. Each `cell` holds information about a segment of text.
* `Write()`: The main method for feeding data to the `tabwriter`.
* `Flush()`:  The method to finalize processing and output the formatted text.
* `Init()` and `NewWriter()`: Initialization functions.

**3. Dissecting the Alignment Logic:**

The comments about cells, tabs, and the examples are crucial. I'd pay close attention to:

* How cells are defined (terminated by tabs or line breaks).
* The concept of contiguous lines forming a column.
* The distinction between tab-terminated and tab-separated. The example with `aaaa|bbb|d` helps illustrate this.
* The `format()` method is likely where the core alignment calculations happen. I would skim its logic to understand how it determines column widths.

**4. Analyzing the Flags:**

The `const` block defining the flags is important. I'd try to understand what each flag does:

* `FilterHTML`:  Handles HTML tags and entities.
* `StripEscape`: Removes escape characters.
* `AlignRight`: Right-aligns columns.
* `DiscardEmptyColumns`: Removes columns with only vertical tabs.
* `TabIndent`: Uses tabs for leading indentation.
* `Debug`: Adds vertical bars between columns.

**5. Inferring Functionality and Providing Examples:**

Now, I'd start connecting the pieces to explain the functionality and provide code examples.

* **Basic Tab Alignment:**  The simplest case. Show how tabs are translated into spaces for alignment.
* **Handling Multiple Lines:** Demonstrate how the `tabwriter` considers multiple lines to align columns.
* **HTML Filtering:**  Create an example showing how HTML tags are ignored in width calculations, but entities are counted.
* **Escape Sequences:** Show how to use the `Escape` character to treat tabs literally.
* **`DiscardEmptyColumns`:**  Illustrate the effect of this flag.

For each example, I'd think about:

* **Input:**  A representative string with tabs.
* **Expected Output:** How the `tabwriter` should format it based on the chosen configuration.
* **Go Code:** The `main` function using `tabwriter.NewWriter` and writing the input.

**6. Identifying Error-Prone Areas:**

Based on the understanding of how `tabwriter` works, I'd consider common mistakes:

* **Forgetting to `Flush()`:**  A classic issue with buffered writers.
* **Misunderstanding Tab Termination:**  The difference between tab-terminated and tab-separated is a key point of confusion.
* **Assuming Fixed-Width Tab Stops:**  `tabwriter` doesn't work like a simple tab expansion.
* **Incorrectly Using Escape Characters:**  Forgetting to close escape sequences.

**7. Addressing Command-Line Arguments:**

The code itself doesn't explicitly handle command-line arguments. The configuration happens programmatically through the `NewWriter` function. Therefore, the explanation should focus on how these parameters are used within the Go code.

**8. Structuring the Output:**

Finally, I'd organize the information clearly, using headings, code blocks, and explanations, as requested by the prompt. I'd make sure to address all the specific points raised in the prompt (functionality, Go examples, assumptions, command-line arguments, common errors). Using clear and concise language is essential.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the `tabwriter` just replaces tabs with a fixed number of spaces.
* **Correction:** The "Elastic Tabstops" mention and the example with varying lengths suggest a more dynamic alignment. The code confirms this by calculating column widths.
* **Initial thought:**  Command-line arguments are directly handled within the `tabwriter` package.
* **Correction:** The code shows that configuration happens through function calls. The explanation needs to reflect this.
* **Reviewing Examples:**  Ensure that the input and output examples clearly illustrate the intended functionality and the effect of different flags. Double-check the output against the expected behavior.

By following these steps, the analysis becomes systematic and covers all the essential aspects of the `tabwriter` package, leading to a comprehensive and accurate explanation.
`go/src/text/tabwriter/tabwriter.go` 文件实现了 Go 语言的 `text/tabwriter` 包，该包提供了一个 `Writer` 类型，它可以作为一个写入过滤器，将输入中以制表符分隔的列对齐。

以下是 `tabwriter.Writer` 的主要功能：

1. **制表符对齐 (Tab Alignment):**  这是核心功能。`Writer` 会分析输入的文本，识别由水平制表符 (`\t`) 或垂直制表符 (`\v`) 分隔的单元格，以及由换行符 (`\n`) 或换页符 (`\f`) 分隔的行。它会插入必要的填充，使得同一列中的单元格具有相同的宽度，从而实现列的对齐。

2. **弹性制表符 (Elastic Tabstops):**  该包使用了 Elastic Tabstops 算法。这意味着列宽是动态计算的，取决于该列中最宽单元格的宽度。

3. **多种行尾符支持:**  支持 `\n` (换行) 和 `\f` (换页) 作为行尾符。`\f` 除了作为行尾符外，还会强制刷新缓冲区，立即输出当前所有已缓冲的内容。

4. **HTML 过滤 (Optional):**  通过设置 `FilterHTML` 标志，`Writer` 可以忽略 HTML 标签的宽度（视为宽度为 0），并将 HTML 实体（例如 `&nbsp;`）视为宽度为 1 的字符。

5. **转义处理 (Escape Handling):**  可以使用 `Escape` 字符 (默认是 `\xff`) 来转义文本段。被转义的文本段中的制表符和换行符不会被解释为列分隔符或行尾符，而是作为普通字符处理。通过 `StripEscape` 标志，可以选择在输出中去除转义字符。

6. **右对齐 (Optional):**  通过设置 `AlignRight` 标志，可以实现列的右对齐。默认是左对齐。

7. **丢弃空列 (Optional):**  通过设置 `DiscardEmptyColumns` 标志，可以丢弃完全由垂直制表符分隔的空列。由水平制表符分隔的空列不受此标志影响。

8. **制表符缩进 (Optional):**  通过设置 `TabIndent` 标志，可以使用制表符来填充前导空单元格的缩进。

9. **调试模式 (Optional):**  通过设置 `Debug` 标志，可以在列之间打印竖线 (`|`)，方便调试输出的对齐情况。

**`tabwriter` 的 Go 语言功能实现：写入过滤器 (Write Filter)**

`tabwriter.Writer` 实现了 `io.Writer` 接口，它充当一个写入过滤器。你可以将要格式化的数据写入 `Writer`，`Writer` 会对数据进行处理并将其写入到你提供的底层 `io.Writer`。

**Go 代码示例：基本的制表符对齐**

```go
package main

import (
	"fmt"
	"os"
	"text/tabwriter"
)

func main() {
	w := tabwriter.NewWriter(os.Stdout, 1, 8, 1, ' ', 0)
	defer w.Flush()

	fmt.Fprintln(w, "姓名\t年龄\t城市")
	fmt.Fprintln(w, "张三\t25\t北京")
	fmt.Fprintln(w, "李四\t30\t上海")
	fmt.Fprintln(w, "王五\t28\t广州")
}
```

**假设的输出：**

```
姓名    年龄  城市
张三    25   北京
李四    30   上海
王五    28   广州
```

**代码解释：**

* `tabwriter.NewWriter(os.Stdout, 1, 8, 1, ' ', 0)` 创建一个新的 `Writer`。
    * `os.Stdout`:  指定输出目标为标准输出。
    * `1`: `minwidth`，最小单元格宽度，包括任何填充。
    * `8`: `tabwidth`，制表符的宽度，相当于多少个空格。
    * `1`: `padding`，单元格之间的额外填充空格数。
    * `' '`: `padchar`，用于填充的字符，这里是空格。
    * `0`: `flags`，没有设置任何标志。
* `fmt.Fprintln(w, ...)` 将带有制表符分隔的数据写入 `Writer`。
* `defer w.Flush()` 确保在 `main` 函数结束前刷新缓冲区，将所有格式化后的数据写入 `os.Stdout`。

**Go 代码示例：使用 HTML 过滤**

```go
package main

import (
	"fmt"
	"os"
	"text/tabwriter"
)

func main() {
	w := tabwriter.NewWriter(os.Stdout, 1, 8, 1, ' ', tabwriter.FilterHTML)
	defer w.Flush()

	fmt.Fprintln(w, "项目\t描述")
	fmt.Fprintln(w, "<b>标题</b>\t这是一个 <em>强调的</em> 文本 &nbsp; ")
	fmt.Fprintln(w, "链接\t<a href=\"https://example.com\">示例</a>")
}
```

**假设的输出：**

```
项目        描述
<b>标题</b>  这是一个 <em>强调的</em> 文本  
链接        <a href="https://example.com">示例</a>
```

**代码解释：**

* `tabwriter.NewWriter(os.Stdout, 1, 8, 1, ' ', tabwriter.FilterHTML)` 创建 `Writer` 时设置了 `tabwriter.FilterHTML` 标志。
* 可以看到 HTML 标签 `<b>`, `<em>`, `<a>` 没有影响列的对齐，而 HTML 实体 `&nbsp;` 被视为一个字符的宽度。

**代码推理：内部缓冲区和格式化**

`tabwriter.Writer` 需要缓冲输入，因为它需要查看后续的行才能确定合适的列宽。当你调用 `Write` 方法时，数据会被添加到内部缓冲区 (`b.buf`)，并被解析成单元格 (`cell`) 和行 (`lines`). 实际的格式化和输出发生在 `Flush` 方法被调用时。`Flush` 方法会遍历缓冲的行和单元格，根据配置计算列宽，并添加必要的填充。

**假设的输入 (用于内部推理):**

```
"姓名\t年龄\n张三\t25\n李四\t30"
```

**内部处理步骤：**

1. **写入 (Write):**
   - 当写入 "姓名\t年龄\n" 时，`Writer` 会将 "姓名" 和 "年龄" 作为两个单元格存储在第一行。
   - 当写入 "张三\t25\n" 时，`Writer` 会将 "张三" 和 "25" 作为两个单元格存储在第二行。
   - 当写入 "李四\t30" 时，`Writer` 会将 "李四" 和 "30" 作为两个单元格存储在第三行（尚未遇到行尾符）。

2. **刷新 (Flush):**
   - `Flush` 方法会分析 `b.lines` 中的数据。
   - 它会计算第一列的最大宽度（"姓名" 的宽度），以及第二列的最大宽度（"年龄" 的宽度）。
   - 它会根据 `minwidth`、`tabwidth` 和 `padding` 参数，以及计算出的最大宽度，来决定每个单元格需要添加多少填充。
   - 最后，它会将格式化后的文本写入到 `output` (例如 `os.Stdout`)。

**命令行参数的具体处理**

`text/tabwriter` 包本身**不直接处理命令行参数**。它的配置是通过 `tabwriter.NewWriter` 函数的参数来完成的。如果你想让用户通过命令行参数来控制 `tabwriter` 的行为，你需要在你的程序中解析这些参数，并将解析后的值传递给 `NewWriter` 函数。

例如，你可以使用 `flag` 包来处理命令行参数：

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
)

func main() {
	minwidth := flag.Int("minwidth", 1, "最小单元格宽度")
	tabwidth := flag.Int("tabwidth", 8, "制表符宽度")
	padding := flag.Int("padding", 1, "单元格填充")
	padchar := flag.String("padchar", " ", "填充字符")
	flag.Parse()

	w := tabwriter.NewWriter(os.Stdout, *minwidth, *tabwidth, *padding, (*padchar)[0], 0)
	defer w.Flush()

	fmt.Fprintln(w, "列1\t列2")
	fmt.Fprintln(w, "数据A\t数据B")
}
```

用户可以通过以下命令行运行程序来改变 `tabwriter` 的行为：

```bash
go run main.go -minwidth=5 -tabwidth=4 -padding=2 -padchar='.'
```

**使用者易犯错的点**

1. **忘记调用 `Flush()`:**  `tabwriter` 会缓冲数据，直到 `Flush()` 被调用才会真正输出。如果忘记调用 `Flush()`，部分或全部数据可能不会显示。

   ```go
   package main

   import (
       "fmt"
       "os"
       "text/tabwriter"
   )

   func main() {
       w := tabwriter.NewWriter(os.Stdout, 1, 8, 1, ' ', 0)
       fmt.Fprintln(w, "A\tB")
       // 忘记调用 w.Flush()
   }
   ```

   在这个例子中，可能不会看到任何输出，因为数据仍然在缓冲区中。

2. **误解制表符的作用:**  `tabwriter` 是基于制表符来分隔列的。如果你的输入没有使用制表符，或者使用了空格或其他分隔符，`tabwriter` 就无法正确地对齐列。

   ```go
   package main

   import (
       "fmt"
       "os"
       "text/tabwriter"
   )

   func main() {
       w := tabwriter.NewWriter(os.Stdout, 1, 8, 1, ' ', 0)
       defer w.Flush()
       fmt.Fprintln(w, "列1 列2") // 使用空格分隔，tabwriter 不会对其
   }
   ```

   输出不会被对齐，因为 `tabwriter` 期望的是制表符 (`\t`)。

3. **不理解 `minwidth`、`tabwidth` 和 `padding` 的作用:**  这些参数控制着对齐的方式。如果设置不当，可能会导致输出不符合预期。例如，`minwidth` 太小可能会导致列重叠。

4. **混淆水平制表符和垂直制表符的作用:**  水平制表符 (`\t`) 用于分隔同一行内的列，而垂直制表符 (`\v`) 也被视为列分隔符，但它不会像水平制表符那样参与到列宽的计算中，更多用于标记一个软性的列分隔。空列被垂直制表符分隔时，可能会受到 `DiscardEmptyColumns` 标志的影响。

总而言之，`text/tabwriter` 包提供了一种灵活的方式来格式化文本输出，使其具有良好的列对齐效果。理解其工作原理和配置参数对于正确使用它是非常重要的。

Prompt: 
```
这是路径为go/src/text/tabwriter/tabwriter.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tabwriter implements a write filter (tabwriter.Writer) that
// translates tabbed columns in input into properly aligned text.
//
// The package is using the Elastic Tabstops algorithm described at
// http://nickgravgaard.com/elastictabstops/index.html.
//
// The text/tabwriter package is frozen and is not accepting new features.
package tabwriter

import (
	"fmt"
	"io"
	"unicode/utf8"
)

// ----------------------------------------------------------------------------
// Filter implementation

// A cell represents a segment of text terminated by tabs or line breaks.
// The text itself is stored in a separate buffer; cell only describes the
// segment's size in bytes, its width in runes, and whether it's an htab
// ('\t') terminated cell.
type cell struct {
	size  int  // cell size in bytes
	width int  // cell width in runes
	htab  bool // true if the cell is terminated by an htab ('\t')
}

// A Writer is a filter that inserts padding around tab-delimited
// columns in its input to align them in the output.
//
// The Writer treats incoming bytes as UTF-8-encoded text consisting
// of cells terminated by horizontal ('\t') or vertical ('\v') tabs,
// and newline ('\n') or formfeed ('\f') characters; both newline and
// formfeed act as line breaks.
//
// Tab-terminated cells in contiguous lines constitute a column. The
// Writer inserts padding as needed to make all cells in a column have
// the same width, effectively aligning the columns. It assumes that
// all characters have the same width, except for tabs for which a
// tabwidth must be specified. Column cells must be tab-terminated, not
// tab-separated: non-tab terminated trailing text at the end of a line
// forms a cell but that cell is not part of an aligned column.
// For instance, in this example (where | stands for a horizontal tab):
//
//	aaaa|bbb|d
//	aa  |b  |dd
//	a   |
//	aa  |cccc|eee
//
// the b and c are in distinct columns (the b column is not contiguous
// all the way). The d and e are not in a column at all (there's no
// terminating tab, nor would the column be contiguous).
//
// The Writer assumes that all Unicode code points have the same width;
// this may not be true in some fonts or if the string contains combining
// characters.
//
// If [DiscardEmptyColumns] is set, empty columns that are terminated
// entirely by vertical (or "soft") tabs are discarded. Columns
// terminated by horizontal (or "hard") tabs are not affected by
// this flag.
//
// If a Writer is configured to filter HTML, HTML tags and entities
// are passed through. The widths of tags and entities are
// assumed to be zero (tags) and one (entities) for formatting purposes.
//
// A segment of text may be escaped by bracketing it with [Escape]
// characters. The tabwriter passes escaped text segments through
// unchanged. In particular, it does not interpret any tabs or line
// breaks within the segment. If the [StripEscape] flag is set, the
// Escape characters are stripped from the output; otherwise they
// are passed through as well. For the purpose of formatting, the
// width of the escaped text is always computed excluding the Escape
// characters.
//
// The formfeed character acts like a newline but it also terminates
// all columns in the current line (effectively calling [Writer.Flush]). Tab-
// terminated cells in the next line start new columns. Unless found
// inside an HTML tag or inside an escaped text segment, formfeed
// characters appear as newlines in the output.
//
// The Writer must buffer input internally, because proper spacing
// of one line may depend on the cells in future lines. Clients must
// call Flush when done calling [Writer.Write].
type Writer struct {
	// configuration
	output   io.Writer
	minwidth int
	tabwidth int
	padding  int
	padbytes [8]byte
	flags    uint

	// current state
	buf     []byte   // collected text excluding tabs or line breaks
	pos     int      // buffer position up to which cell.width of incomplete cell has been computed
	cell    cell     // current incomplete cell; cell.width is up to buf[pos] excluding ignored sections
	endChar byte     // terminating char of escaped sequence (Escape for escapes, '>', ';' for HTML tags/entities, or 0)
	lines   [][]cell // list of lines; each line is a list of cells
	widths  []int    // list of column widths in runes - re-used during formatting
}

// addLine adds a new line.
// flushed is a hint indicating whether the underlying writer was just flushed.
// If so, the previous line is not likely to be a good indicator of the new line's cells.
func (b *Writer) addLine(flushed bool) {
	// Grow slice instead of appending,
	// as that gives us an opportunity
	// to re-use an existing []cell.
	if n := len(b.lines) + 1; n <= cap(b.lines) {
		b.lines = b.lines[:n]
		b.lines[n-1] = b.lines[n-1][:0]
	} else {
		b.lines = append(b.lines, nil)
	}

	if !flushed {
		// The previous line is probably a good indicator
		// of how many cells the current line will have.
		// If the current line's capacity is smaller than that,
		// abandon it and make a new one.
		if n := len(b.lines); n >= 2 {
			if prev := len(b.lines[n-2]); prev > cap(b.lines[n-1]) {
				b.lines[n-1] = make([]cell, 0, prev)
			}
		}
	}
}

// Reset the current state.
func (b *Writer) reset() {
	b.buf = b.buf[:0]
	b.pos = 0
	b.cell = cell{}
	b.endChar = 0
	b.lines = b.lines[0:0]
	b.widths = b.widths[0:0]
	b.addLine(true)
}

// Internal representation (current state):
//
// - all text written is appended to buf; tabs and line breaks are stripped away
// - at any given time there is a (possibly empty) incomplete cell at the end
//   (the cell starts after a tab or line break)
// - cell.size is the number of bytes belonging to the cell so far
// - cell.width is text width in runes of that cell from the start of the cell to
//   position pos; html tags and entities are excluded from this width if html
//   filtering is enabled
// - the sizes and widths of processed text are kept in the lines list
//   which contains a list of cells for each line
// - the widths list is a temporary list with current widths used during
//   formatting; it is kept in Writer because it's re-used
//
//                    |<---------- size ---------->|
//                    |                            |
//                    |<- width ->|<- ignored ->|  |
//                    |           |             |  |
// [---processed---tab------------<tag>...</tag>...]
// ^                  ^                         ^
// |                  |                         |
// buf                start of incomplete cell  pos

// Formatting can be controlled with these flags.
const (
	// Ignore html tags and treat entities (starting with '&'
	// and ending in ';') as single characters (width = 1).
	FilterHTML uint = 1 << iota

	// Strip Escape characters bracketing escaped text segments
	// instead of passing them through unchanged with the text.
	StripEscape

	// Force right-alignment of cell content.
	// Default is left-alignment.
	AlignRight

	// Handle empty columns as if they were not present in
	// the input in the first place.
	DiscardEmptyColumns

	// Always use tabs for indentation columns (i.e., padding of
	// leading empty cells on the left) independent of padchar.
	TabIndent

	// Print a vertical bar ('|') between columns (after formatting).
	// Discarded columns appear as zero-width columns ("||").
	Debug
)

// A [Writer] must be initialized with a call to Init. The first parameter (output)
// specifies the filter output. The remaining parameters control the formatting:
//
//	minwidth	minimal cell width including any padding
//	tabwidth	width of tab characters (equivalent number of spaces)
//	padding		padding added to a cell before computing its width
//	padchar		ASCII char used for padding
//			if padchar == '\t', the Writer will assume that the
//			width of a '\t' in the formatted output is tabwidth,
//			and cells are left-aligned independent of align_left
//			(for correct-looking results, tabwidth must correspond
//			to the tab width in the viewer displaying the result)
//	flags		formatting control
func (b *Writer) Init(output io.Writer, minwidth, tabwidth, padding int, padchar byte, flags uint) *Writer {
	if minwidth < 0 || tabwidth < 0 || padding < 0 {
		panic("negative minwidth, tabwidth, or padding")
	}
	b.output = output
	b.minwidth = minwidth
	b.tabwidth = tabwidth
	b.padding = padding
	for i := range b.padbytes {
		b.padbytes[i] = padchar
	}
	if padchar == '\t' {
		// tab padding enforces left-alignment
		flags &^= AlignRight
	}
	b.flags = flags

	b.reset()

	return b
}

// debugging support (keep code around)
func (b *Writer) dump() {
	pos := 0
	for i, line := range b.lines {
		print("(", i, ") ")
		for _, c := range line {
			print("[", string(b.buf[pos:pos+c.size]), "]")
			pos += c.size
		}
		print("\n")
	}
	print("\n")
}

// local error wrapper so we can distinguish errors we want to return
// as errors from genuine panics (which we don't want to return as errors)
type osError struct {
	err error
}

func (b *Writer) write0(buf []byte) {
	n, err := b.output.Write(buf)
	if n != len(buf) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		panic(osError{err})
	}
}

func (b *Writer) writeN(src []byte, n int) {
	for n > len(src) {
		b.write0(src)
		n -= len(src)
	}
	b.write0(src[0:n])
}

var (
	newline = []byte{'\n'}
	tabs    = []byte("\t\t\t\t\t\t\t\t")
)

func (b *Writer) writePadding(textw, cellw int, useTabs bool) {
	if b.padbytes[0] == '\t' || useTabs {
		// padding is done with tabs
		if b.tabwidth == 0 {
			return // tabs have no width - can't do any padding
		}
		// make cellw the smallest multiple of b.tabwidth
		cellw = (cellw + b.tabwidth - 1) / b.tabwidth * b.tabwidth
		n := cellw - textw // amount of padding
		if n < 0 {
			panic("internal error")
		}
		b.writeN(tabs, (n+b.tabwidth-1)/b.tabwidth)
		return
	}

	// padding is done with non-tab characters
	b.writeN(b.padbytes[0:], cellw-textw)
}

var vbar = []byte{'|'}

func (b *Writer) writeLines(pos0 int, line0, line1 int) (pos int) {
	pos = pos0
	for i := line0; i < line1; i++ {
		line := b.lines[i]

		// if TabIndent is set, use tabs to pad leading empty cells
		useTabs := b.flags&TabIndent != 0

		for j, c := range line {
			if j > 0 && b.flags&Debug != 0 {
				// indicate column break
				b.write0(vbar)
			}

			if c.size == 0 {
				// empty cell
				if j < len(b.widths) {
					b.writePadding(c.width, b.widths[j], useTabs)
				}
			} else {
				// non-empty cell
				useTabs = false
				if b.flags&AlignRight == 0 { // align left
					b.write0(b.buf[pos : pos+c.size])
					pos += c.size
					if j < len(b.widths) {
						b.writePadding(c.width, b.widths[j], false)
					}
				} else { // align right
					if j < len(b.widths) {
						b.writePadding(c.width, b.widths[j], false)
					}
					b.write0(b.buf[pos : pos+c.size])
					pos += c.size
				}
			}
		}

		if i+1 == len(b.lines) {
			// last buffered line - we don't have a newline, so just write
			// any outstanding buffered data
			b.write0(b.buf[pos : pos+b.cell.size])
			pos += b.cell.size
		} else {
			// not the last line - write newline
			b.write0(newline)
		}
	}
	return
}

// Format the text between line0 and line1 (excluding line1); pos
// is the buffer position corresponding to the beginning of line0.
// Returns the buffer position corresponding to the beginning of
// line1 and an error, if any.
func (b *Writer) format(pos0 int, line0, line1 int) (pos int) {
	pos = pos0
	column := len(b.widths)
	for this := line0; this < line1; this++ {
		line := b.lines[this]

		if column >= len(line)-1 {
			continue
		}
		// cell exists in this column => this line
		// has more cells than the previous line
		// (the last cell per line is ignored because cells are
		// tab-terminated; the last cell per line describes the
		// text before the newline/formfeed and does not belong
		// to a column)

		// print unprinted lines until beginning of block
		pos = b.writeLines(pos, line0, this)
		line0 = this

		// column block begin
		width := b.minwidth // minimal column width
		discardable := true // true if all cells in this column are empty and "soft"
		for ; this < line1; this++ {
			line = b.lines[this]
			if column >= len(line)-1 {
				break
			}
			// cell exists in this column
			c := line[column]
			// update width
			if w := c.width + b.padding; w > width {
				width = w
			}
			// update discardable
			if c.width > 0 || c.htab {
				discardable = false
			}
		}
		// column block end

		// discard empty columns if necessary
		if discardable && b.flags&DiscardEmptyColumns != 0 {
			width = 0
		}

		// format and print all columns to the right of this column
		// (we know the widths of this column and all columns to the left)
		b.widths = append(b.widths, width) // push width
		pos = b.format(pos, line0, this)
		b.widths = b.widths[0 : len(b.widths)-1] // pop width
		line0 = this
	}

	// print unprinted lines until end
	return b.writeLines(pos, line0, line1)
}

// Append text to current cell.
func (b *Writer) append(text []byte) {
	b.buf = append(b.buf, text...)
	b.cell.size += len(text)
}

// Update the cell width.
func (b *Writer) updateWidth() {
	b.cell.width += utf8.RuneCount(b.buf[b.pos:])
	b.pos = len(b.buf)
}

// To escape a text segment, bracket it with Escape characters.
// For instance, the tab in this string "Ignore this tab: \xff\t\xff"
// does not terminate a cell and constitutes a single character of
// width one for formatting purposes.
//
// The value 0xff was chosen because it cannot appear in a valid UTF-8 sequence.
const Escape = '\xff'

// Start escaped mode.
func (b *Writer) startEscape(ch byte) {
	switch ch {
	case Escape:
		b.endChar = Escape
	case '<':
		b.endChar = '>'
	case '&':
		b.endChar = ';'
	}
}

// Terminate escaped mode. If the escaped text was an HTML tag, its width
// is assumed to be zero for formatting purposes; if it was an HTML entity,
// its width is assumed to be one. In all other cases, the width is the
// unicode width of the text.
func (b *Writer) endEscape() {
	switch b.endChar {
	case Escape:
		b.updateWidth()
		if b.flags&StripEscape == 0 {
			b.cell.width -= 2 // don't count the Escape chars
		}
	case '>': // tag of zero width
	case ';':
		b.cell.width++ // entity, count as one rune
	}
	b.pos = len(b.buf)
	b.endChar = 0
}

// Terminate the current cell by adding it to the list of cells of the
// current line. Returns the number of cells in that line.
func (b *Writer) terminateCell(htab bool) int {
	b.cell.htab = htab
	line := &b.lines[len(b.lines)-1]
	*line = append(*line, b.cell)
	b.cell = cell{}
	return len(*line)
}

func (b *Writer) handlePanic(err *error, op string) {
	if e := recover(); e != nil {
		if op == "Flush" {
			// If Flush ran into a panic, we still need to reset.
			b.reset()
		}
		if nerr, ok := e.(osError); ok {
			*err = nerr.err
			return
		}
		panic(fmt.Sprintf("tabwriter: panic during %s (%v)", op, e))
	}
}

// Flush should be called after the last call to [Writer.Write] to ensure
// that any data buffered in the [Writer] is written to output. Any
// incomplete escape sequence at the end is considered
// complete for formatting purposes.
func (b *Writer) Flush() error {
	return b.flush()
}

// flush is the internal version of Flush, with a named return value which we
// don't want to expose.
func (b *Writer) flush() (err error) {
	defer b.handlePanic(&err, "Flush")
	b.flushNoDefers()
	return nil
}

// flushNoDefers is like flush, but without a deferred handlePanic call. This
// can be called from other methods which already have their own deferred
// handlePanic calls, such as Write, and avoid the extra defer work.
func (b *Writer) flushNoDefers() {
	// add current cell if not empty
	if b.cell.size > 0 {
		if b.endChar != 0 {
			// inside escape - terminate it even if incomplete
			b.endEscape()
		}
		b.terminateCell(false)
	}

	// format contents of buffer
	b.format(0, 0, len(b.lines))
	b.reset()
}

var hbar = []byte("---\n")

// Write writes buf to the writer b.
// The only errors returned are ones encountered
// while writing to the underlying output stream.
func (b *Writer) Write(buf []byte) (n int, err error) {
	defer b.handlePanic(&err, "Write")

	// split text into cells
	n = 0
	for i, ch := range buf {
		if b.endChar == 0 {
			// outside escape
			switch ch {
			case '\t', '\v', '\n', '\f':
				// end of cell
				b.append(buf[n:i])
				b.updateWidth()
				n = i + 1 // ch consumed
				ncells := b.terminateCell(ch == '\t')
				if ch == '\n' || ch == '\f' {
					// terminate line
					b.addLine(ch == '\f')
					if ch == '\f' || ncells == 1 {
						// A '\f' always forces a flush. Otherwise, if the previous
						// line has only one cell which does not have an impact on
						// the formatting of the following lines (the last cell per
						// line is ignored by format()), thus we can flush the
						// Writer contents.
						b.flushNoDefers()
						if ch == '\f' && b.flags&Debug != 0 {
							// indicate section break
							b.write0(hbar)
						}
					}
				}

			case Escape:
				// start of escaped sequence
				b.append(buf[n:i])
				b.updateWidth()
				n = i
				if b.flags&StripEscape != 0 {
					n++ // strip Escape
				}
				b.startEscape(Escape)

			case '<', '&':
				// possibly an html tag/entity
				if b.flags&FilterHTML != 0 {
					// begin of tag/entity
					b.append(buf[n:i])
					b.updateWidth()
					n = i
					b.startEscape(ch)
				}
			}

		} else {
			// inside escape
			if ch == b.endChar {
				// end of tag/entity
				j := i + 1
				if ch == Escape && b.flags&StripEscape != 0 {
					j = i // strip Escape
				}
				b.append(buf[n:j])
				n = i + 1 // ch consumed
				b.endEscape()
			}
		}
	}

	// append leftover text
	b.append(buf[n:])
	n = len(buf)
	return
}

// NewWriter allocates and initializes a new [Writer].
// The parameters are the same as for the Init function.
func NewWriter(output io.Writer, minwidth, tabwidth, padding int, padchar byte, flags uint) *Writer {
	return new(Writer).Init(output, minwidth, tabwidth, padding, padchar, flags)
}

"""



```