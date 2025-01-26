Response:
Let's break down the thought process for analyzing the provided Go code and generating the comprehensive answer.

1. **Understanding the Goal:** The core request is to understand the functionality of the given Go code snippet, which is a part of `asmfmt.go`. This means identifying its purpose, how it works, potential use cases, and common pitfalls.

2. **Initial Code Scan and Keyword Spotting:**  I'd start by quickly scanning the code, looking for prominent keywords and structures:
    * `package asmfmt`:  Indicates this is part of a package named `asmfmt`, likely related to formatting assembly code.
    * `io.Reader`, `[]byte`, `error`: Suggests the function processes input and produces formatted output, potentially with error handling.
    * `bufio.Reader`, `bytes.Buffer`:  Standard Go libraries for efficient input/output.
    * `fstate`: A struct with fields like `indentation`, `comments`, `queued`, suggesting internal state management for formatting.
    * `statement`:  A struct holding parts of an assembly instruction, like `instruction`, `params`, `comment`.
    * Function names like `Format`, `addLine`, `flush`, `newStatement`, `formatStatements`:  These hint at the processing pipeline.
    * Comments like "Block comment", "Indentation level":  Provide direct clues about the code's intent.

3. **Analyzing the `Format` Function:** This seems like the entry point.
    * It takes an `io.Reader` as input.
    * It creates a `bufio.Reader` for efficient reading.
    * It initializes an `fstate`.
    * It reads lines from the input using `src.ReadLine()`.
    * It calls `state.addLine()` for each line.
    * It calls `state.flush()` at the end.
    * It returns the formatted output from the `bytes.Buffer`.
    * **Hypothesis:** This function reads assembly code, line by line, and processes it using the `fstate`.

4. **Analyzing the `fstate` Struct and `addLine` Function:** This is where the core formatting logic resides.
    * `fstate` holds the output buffer, indentation level, queued statements, comments, and a map of defined macros. This strongly suggests the code is trying to understand the structure of the assembly language.
    * `addLine` handles different types of lines:
        * Block comments (`/* ... */`):  Special handling for multi-line comments.
        * Single-line comments (`//`):  Extraction and queuing.
        * Empty lines:  Managing spacing.
        * Assembly instructions:  Parsing and storing in the `queued` slice.
        * **Key Observation:** The comment within `addLine` explicitly mentions that it's a "hodgepodge" and needs a rewrite with proper parsing. This signals that the current approach might be heuristic and not fully robust.

5. **Analyzing the `statement` Struct and `newStatement` Function:** This focuses on parsing individual assembly lines.
    * `statement` breaks down an assembly line into its components.
    * `newStatement` splits the line into instruction, parameters, and comment.
    * It handles macro definitions (`#define`).
    * It detects function calls and labels.
    * It handles line continuations (`\`).
    * **Hypothesis:** This function attempts to understand the grammatical structure of assembly language, identifying different elements.

6. **Analyzing the `flush` and `formatStatements` Functions:** These handle the output formatting.
    * `flush` writes queued comments and formatted statements to the output buffer, applying indentation.
    * `formatStatements` calculates the maximum lengths of instructions and parameters to align the output. It also handles comment alignment and line continuation.
    * **Hypothesis:** These functions are responsible for the visual presentation of the formatted assembly code.

7. **Inferring the Go Language Feature:** Based on the file name (`asmfmt.go`) and the code's logic (handling assembly instructions, labels, comments, and formatting), it's highly likely that this code implements an **assembly code formatter**. It takes raw assembly code as input and produces a more consistently formatted version.

8. **Generating Go Code Examples:**  To illustrate the functionality, I'd create simple assembly input and show the expected formatted output. This would cover different scenarios like comments, labels, instructions, and line continuations.

9. **Identifying Command-Line Arguments:**  The provided code snippet doesn't explicitly handle command-line arguments. The `Format` function takes an `io.Reader`, which could come from a file or standard input. Therefore, I'd explain that command-line handling would likely be in the `main` package that *uses* this `asmfmt` package.

10. **Identifying Potential Errors:** Based on the code's structure and the comment about being a "hodgepodge," potential error scenarios would involve:
    * Incorrect parsing of complex assembly syntax.
    * Issues with very long lines or deeply nested comments.
    * Edge cases in line continuation or macro definitions.

11. **Structuring the Answer:**  Finally, I'd organize the findings into a clear and structured answer, addressing each part of the original request:
    * Functionality description.
    * Go language feature identification.
    * Code examples with input/output.
    * Explanation of command-line argument handling (or lack thereof in the provided code).
    * Identification of potential user errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe it's just a simple comment stripper. **Correction:** The presence of `fstate`, `statement`, and formatting logic indicates a more complex task than just removing comments.
* **Initial thought:** The command-line arguments are handled within this code. **Correction:**  The `Format` function takes an `io.Reader`, suggesting it's designed to be a library function. Command-line handling would be external.
* **Initial thought:** Focus only on the happy path. **Correction:** The request specifically asks for potential errors, so I need to consider cases where the parsing might fail or produce unexpected results.

By following this structured analysis and iterative refinement, I can arrive at a comprehensive and accurate answer to the user's request.
这段Go语言实现是 `asmfmt` 包的一部分，其主要功能是**格式化汇编语言代码**。

更具体地说，`asmfmt.go` 文件中的代码实现了将输入的汇编代码进行标准化格式处理，使其更易读。

以下是其主要功能点的详细说明：

1. **读取汇编代码：** `Format` 函数接收一个 `io.Reader` 接口作为输入，这意味着它可以从任何实现了 `io.Reader` 的地方读取汇编代码，例如文件或标准输入。

2. **逐行处理：** 代码通过 `bufio.Reader` 逐行读取输入的汇编代码。

3. **状态管理 (`fstate` 结构体)：** 使用 `fstate` 结构体来维护格式化过程中的状态信息，包括：
    * `out`:  一个 `bytes.Buffer`，用于存储格式化后的输出。
    * `insideBlock`:  一个布尔值，指示当前是否在块注释 (`/* ... */`) 内部。
    * `indentation`:  当前的缩进级别。
    * `lastEmpty`:  一个布尔值，指示上一行是否为空行。
    * `lastComment`:  一个布尔值，指示上一行是否为注释行。
    * `lastStar`:  一个布尔值，用于处理块注释中以星号开头的行。
    * `lastLabel`:  一个布尔值，指示上一行是否为标签。
    * `anyContents`:  一个布尔值，指示是否已经处理过非空行。
    * `lastContinued`:  一个布尔值，指示上一行是否是行延续 (`\`)。
    * `queued`:  一个 `statement` 类型的切片，用于暂存需要格式化的语句。
    * `comments`:  一个字符串切片，用于暂存遇到的注释。
    * `defines`:  一个 `map`，用于存储 `#define` 定义的宏。

4. **解析汇编语句 (`statement` 结构体和 `newStatement` 函数)：**  `statement` 结构体用于表示一个汇编语句，包含指令、参数和注释等信息。`newStatement` 函数用于解析输入的字符串，并将其转换为 `statement` 结构体。它可以识别：
    * 指令 (instruction)
    * 参数 (params)
    * 注释 (comment)
    * 宏定义 (function，通过 `#define` 或其他方式推断)
    * 行延续 (continued)
    * 仅注释的行延续 (contComment)

5. **格式化逻辑 (`addLine` 函数和 `formatStatements` 函数)：** `addLine` 函数负责处理每一行输入的汇编代码，并根据其类型（注释、空行、指令等）更新 `fstate` 的状态。`formatStatements` 函数接收一个 `statement` 切片，并根据一定的规则（例如对齐指令、参数和注释）将其格式化为字符串切片。

6. **处理注释：** 可以处理单行注释 (`//`) 和多行块注释 (`/* ... */`)。对于块注释，它会尝试保持星号对齐。

7. **处理空行：** 限制连续空行的数量，并确保不会以空行开头。

8. **处理标签：**  识别汇编标签（以冒号结尾），并将其放在单独的行上。

9. **处理行延续：**  识别以反斜杠 `\` 结尾的行，并将其与下一行合并处理，并对延续行进行适当的缩进和注释对齐。

10. **处理宏定义：** 可以识别 `#define` 定义的宏，并在后续处理中进行识别。

11. **指令和参数对齐：**  `formatStatements` 函数会计算最长的指令和参数的长度，以便在输出时进行对齐，提高可读性。

12. **错误处理：**  `Format` 函数会检查输入中是否包含零字节，如果包含则返回错误，因为这通常不是合法的汇编文件。

**推理 Go 语言功能实现：汇编代码格式化工具**

`asmfmt.go` 实现了汇编代码的格式化功能，类似于 Go 语言自带的 `gofmt` 工具，但专门用于汇编语言。它可以帮助开发者维护一致的汇编代码风格，提高代码的可读性和维护性。

**Go 代码举例说明：**

假设我们有以下未格式化的汇编代码（input.s）：

```assembly
// This is a comment
MOV  AX,  BX  // Move BX to AX
label:
  ADD  CX, DX \ // Add DX to CX
  // Continue the addition
  INC  CX
/*
This is a
multi-line comment
*/
  RET
```

使用 `asmfmt` 包进行格式化的 Go 代码如下：

```go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/klauspost/asmfmt"
)

func main() {
	input := `// This is a comment
MOV  AX,  BX  // Move BX to AX
label:
  ADD  CX, DX \ // Add DX to CX
  // Continue the addition
  INC  CX
/*
This is a
multi-line comment
*/
  RET`

	formatted, err := asmfmt.Format(strings.NewReader(input))
	if err != nil {
		fmt.Println("Error formatting:", err)
		os.Exit(1)
	}
	fmt.Println(string(formatted))
}
```

**假设的输入与输出：**

**输入 (input.s 内容):**

```assembly
// This is a comment
MOV  AX,  BX  // Move BX to AX
label:
  ADD  CX, DX \ // Add DX to CX
  // Continue the addition
  INC  CX
/*
This is a
multi-line comment
*/
  RET
```

**输出:**

```assembly
// This is a comment
MOV AX, BX // Move BX to AX
label:
	ADD CX, DX \ // Add DX to CX
	     // Continue the addition
	INC CX
/*
 This is a
 multi-line comment
 */
	RET
```

**命令行参数的具体处理：**

从提供的代码片段来看，`asmfmt.go` 本身并没有直接处理命令行参数。它提供的是一个 `Format` 函数，用于处理 `io.Reader` 中的数据。

要实现一个完整的命令行工具，通常会在一个 `main` 包中调用 `asmfmt.Format` 函数，并使用 `flag` 包或其他方式来处理命令行参数，例如：

```go
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/klauspost/asmfmt"
)

func main() {
	var inputFile string
	flag.StringVar(&inputFile, "i", "", "input assembly file")
	flag.Parse()

	var input []byte
	var err error

	if inputFile == "" {
		// 从标准输入读取
		input, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading from stdin: %v\n", err)
			os.Exit(1)
		}
	} else {
		// 从文件读取
		input, err = ioutil.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading file %s: %v\n", inputFile, err)
			os.Exit(1)
		}
	}

	formatted, err := asmfmt.Format(strings.NewReader(string(input)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error formatting: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(string(formatted))
}
```

在这个例子中：

* 使用 `flag` 包定义了一个 `-i` 参数，用于指定输入文件。
* 如果没有提供 `-i` 参数，则从标准输入读取数据。
* 读取输入后，将其传递给 `asmfmt.Format` 函数进行格式化。
* 格式化后的输出打印到标准输出。

**使用者易犯错的点：**

1. **将 Go 源代码传递给 `asmfmt`：**  `asmfmt` 专门用于格式化汇编代码。如果将 Go 源代码传递给它，它会尝试将其解析为汇编代码，可能会导致错误或不期望的输出。代码中已经有检查 `package` 指令的逻辑来避免这种情况。

   **例子：** 如果你错误地将一个 `.go` 文件作为输入：

   ```bash
   asmfmt my_go_file.go
   ```

   `asmfmt` 会尝试解析其中的内容，并可能会因为遇到 `package` 关键字而报错。

2. **汇编语法错误：** 虽然 `asmfmt` 可以格式化汇编代码，但它并不能纠正汇编语法错误。如果输入的汇编代码本身存在语法错误，格式化后的代码仍然会有这些错误，只是格式可能更整齐。

   **例子：**  如果输入中存在拼写错误的指令，例如 `MOV AX, BXZ`，`asmfmt` 会按照它的理解进行格式化，但汇编器仍然会报错。

3. **依赖特定的汇编语法：**  `asmfmt` 的解析逻辑是基于一定的汇编语法规则。如果输入的汇编代码使用了非常规或特定的汇编语法扩展，`asmfmt` 可能无法正确解析和格式化。

4. **行尾空格或不可见字符：**  虽然 `asmfmt` 会进行 `TrimSpace` 操作，但某些不可见的字符可能仍然会影响解析和格式化的结果。

总而言之，`go/src/github.com/klauspost/asmfmt/asmfmt.go` 实现了一个汇编语言代码格式化工具的核心功能，它通过解析汇编代码的结构，并根据预设的规则进行排版，从而提高汇编代码的可读性和一致性。要作为一个完整的工具使用，通常还需要一个 `main` 包来处理命令行参数和文件 I/O。

Prompt: 
```
这是路径为go/src/github.com/klauspost/asmfmt/asmfmt.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package asmfmt

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// Format the input and return the formatted data.
// If any error is encountered, no data will be returned.
func Format(in io.Reader) ([]byte, error) {
	var src *bufio.Reader
	var ok bool
	src, ok = in.(*bufio.Reader)
	if !ok {
		src = bufio.NewReader(in)
	}
	dst := &bytes.Buffer{}
	state := fstate{out: dst, defines: make(map[string]struct{})}
	for {
		data, _, err := src.ReadLine()
		if err == io.EOF {
			state.flush()
			break
		}
		if err != nil {
			return nil, err
		}
		err = state.addLine(data)
		if err != nil {
			return nil, err
		}
	}
	return dst.Bytes(), nil
}

type fstate struct {
	out           *bytes.Buffer
	insideBlock   bool // Block comment
	indentation   int  // Indentation level
	lastEmpty     bool
	lastComment   bool
	lastStar      bool // Block comment, last line started with a star.
	lastLabel     bool
	anyContents   bool
	lastContinued bool // Last line continued
	queued        []statement
	comments      []string
	defines       map[string]struct{}
}

type statement struct {
	instruction string
	params      []string // Parameters
	comment     string   // Without slashes
	function    bool     // Probably define call
	continued   bool     // Multiline statement, continues on next line
	contComment bool     // Multiline statement, comment only
}

// Add a new input line.
// Since you are looking at ths code:
// This code has grown over a considerable amount of time,
// and deserves a rewrite with proper parsing instead of this hodgepodge.
// Its output is stable, and could be used as reference for a rewrite.
func (f *fstate) addLine(b []byte) error {
	if bytes.Contains(b, []byte{0}) {
		return fmt.Errorf("zero (0) byte in input. file is unlikely an assembler file")
	}
	s := string(b)
	// Inside block comment
	if f.insideBlock {
		defer func() {
			f.lastComment = true
		}()
		if strings.Contains(s, "*/") {
			ends := strings.Index(s, "*/")
			end := s[:ends]
			if strings.HasPrefix(strings.TrimSpace(s), "*") && f.lastStar {
				end = strings.TrimSpace(end) + " "
			}
			end = end + "*/"
			f.insideBlock = false
			s = strings.TrimSpace(s[ends+2:])
			if strings.HasSuffix(s, "\\") {
				end = end + " \\"
				if len(s) == 1 {
					s = ""
				}
			}
			f.out.WriteString(end + "\n")
			if len(s) == 0 {
				return nil
			}
		} else {
			// Insert a space on lines that begin with '*'
			if strings.HasPrefix(strings.TrimSpace(s), "*") {
				s = strings.TrimSpace(s)
				f.out.WriteByte(' ')
				f.lastStar = true
			} else {
				f.lastStar = false
			}
			fmt.Fprintln(f.out, s)
			return nil
		}
	}
	s = strings.TrimSpace(s)

	// Comment is the the only line content.
	if strings.HasPrefix(s, "//") {
		// Non-comment content is now added.
		defer func() {
			f.anyContents = true
			f.lastEmpty = false
			f.lastStar = false
		}()

		s = strings.TrimPrefix(s, "//")
		if len(f.queued) > 0 {
			f.flush()
		}
		// Newline before comments
		if len(f.comments) == 0 {
			f.newLine()
		}

		// Preserve whitespace if the first character after the comment
		// is a whitespace
		ts := strings.TrimSpace(s)
		var q string
		if (ts != s && len(ts) > 0) || (len(s) > 0 && strings.ContainsAny(string(s[0]), `+/`)) {
			q = fmt.Sprint("//" + s)
		} else if len(ts) > 0 {
			// Insert a space before the comment
			q = fmt.Sprint("// " + s)
		} else {
			q = fmt.Sprint("//")
		}
		f.comments = append(f.comments, q)
		f.lastComment = true
		return nil
	}

	// Handle end-of blockcomments.
	if strings.Contains(s, "/*") && !strings.HasSuffix(s, `\`) {
		starts := strings.Index(s, "/*")
		ends := strings.Index(s, "*/")
		lineComment := strings.Index(s, "//")
		if lineComment >= 0 {
			if lineComment < starts {
				goto exitcomm
			}
			if lineComment < ends && !f.insideBlock {
				goto exitcomm
			}
		}
		pre := s[:starts]
		pre = strings.TrimSpace(pre)

		if len(pre) > 0 {
			if strings.HasSuffix(s, `\`) {
				goto exitcomm
			}
			// Add items before the comment section as a line.
			if ends > starts && ends >= len(s)-2 {
				comm := strings.TrimSpace(s[starts+2 : ends])
				return f.addLine([]byte(pre + " //" + comm))
			}
			err := f.addLine([]byte(pre))
			if err != nil {
				return err
			}
		}

		f.flush()

		// Convert single line /* comment */ to // Comment
		if ends > starts && ends >= len(s)-2 {
			return f.addLine([]byte("// " + strings.TrimSpace(s[starts+2:ends])))
		}

		// Comments inside multiline defines.
		if strings.HasSuffix(s, `\`) {
			f.indent()
			s = strings.TrimSpace(strings.TrimSuffix(s, `\`)) + ` \`
		}

		// Otherwise output
		fmt.Fprint(f.out, "/*")
		s = strings.TrimSpace(s[starts+2:])
		f.insideBlock = ends < 0
		f.lastComment = true
		f.lastStar = true
		if len(s) == 0 {
			f.out.WriteByte('\n')
			return nil
		}
		f.out.WriteByte(' ')
		f.out.WriteString(s + "\n")
		return nil
	}
exitcomm:

	if len(s) == 0 {
		f.flush()

		// No more than two empty lines in a row
		// cannot start with NL
		if f.lastEmpty || !f.anyContents {
			return nil
		}
		if f.lastContinued {
			f.indentation = 0
			f.lastContinued = false
		}
		f.lastEmpty = true
		return f.out.WriteByte('\n')
	}

	// Non-comment content is now added.
	defer func() {
		f.anyContents = true
		f.lastEmpty = false
		f.lastStar = false
		f.lastComment = false
	}()

	st := newStatement(s, f.defines)
	if st == nil {
		return nil
	}
	if def := st.define(); def != "" {
		f.defines[def] = struct{}{}
	}
	if st.instruction == "package" {
		if _, ok := f.defines["package"]; !ok {
			return fmt.Errorf("package instruction found. Go files are not supported")
		}
	}

	// Move anything that isn't a comment to the next line
	if st.isLabel() && len(st.params) > 0 && !st.continued {
		idx := strings.Index(s, ":")
		st = newStatement(s[:idx+1], f.defines)
		defer f.addLine([]byte(s[idx+1:]))
	}

	// Should this line be at level 0?
	if st.level0() && !(st.continued && f.lastContinued) {
		if st.isTEXT() && len(f.queued) == 0 && len(f.comments) > 0 {
			f.indentation = 0
		}
		f.flush()

		// Add newline before jump target.
		f.newLine()

		f.indentation = 0
		f.queued = append(f.queued, *st)
		f.flush()

		if !st.isPreProcessor() && !st.isGlobal() {
			f.indentation = 1
		}
		f.lastLabel = true
		return nil
	}

	defer func() {
		f.lastLabel = false
	}()
	f.queued = append(f.queued, *st)
	if st.isTerminator() || (f.lastContinued && !st.continued) {
		// Terminators should always be at level 1
		f.indentation = 1
		f.flush()
		f.indentation = 0
	} else if st.isCommand() {
		// handles cases where a JMP/RET isn't a terminator
		f.indentation = 1
	}
	f.lastContinued = st.continued
	return nil
}

// indent the current line with current indentation.
func (f *fstate) indent() {
	for i := 0; i < f.indentation; i++ {
		f.out.WriteByte('\t')
	}
}

// flush any queued comments and commands
func (f *fstate) flush() {
	for _, line := range f.comments {
		f.indent()
		fmt.Fprintln(f.out, line)
	}
	f.comments = nil
	s := formatStatements(f.queued)
	for _, line := range s {
		f.indent()
		fmt.Fprintln(f.out, line)
	}
	f.queued = nil
}

// Add a newline, unless last line was empty or a comment
func (f *fstate) newLine() {
	// Always newline before comment-only line.
	if !f.lastEmpty && !f.lastComment && !f.lastLabel && f.anyContents {
		f.out.WriteByte('\n')
	}
}

// newStatement will parse a line and return it as a statement.
// Will return nil if the line is empty after whitespace removal.
func newStatement(s string, defs map[string]struct{}) *statement {
	s = strings.TrimSpace(s)
	st := statement{}

	// Fix where a comment start if any
	startcom := strings.Index(s, "//")
	if startcom > 0 {
		st.comment = strings.TrimSpace(s[startcom+2:])
		s = strings.TrimSpace(s[:startcom])
	}

	// Split into fields
	fields := strings.Fields(s)
	if len(fields) < 1 {
		return nil
	}
	st.instruction = fields[0]

	// Handle defined macro calls
	if len(defs) > 0 {
		inst := strings.Split(st.instruction, "(")[0]
		if _, ok := defs[inst]; ok {
			st.function = true
		}
	}
	if strings.HasPrefix(s, "/*") {
		st.function = true
	}
	// We may not have it defined as a macro, if defined in an external
	// .h file, so we try to detect the remaining ones.
	if strings.ContainsAny(st.instruction, "(_") {
		st.function = true
	}
	if len(st.params) > 0 && strings.HasPrefix(st.params[0], "(") {
		st.function = true
	}
	if st.function {
		st.instruction = s
	}

	if st.instruction == "\\" && len(st.comment) > 0 {
		st.instruction = fmt.Sprintf("\\ // %s", st.comment)
		st.comment = ""
		st.function = true
		st.continued = true
		st.contComment = true
	}

	s = strings.TrimPrefix(s, st.instruction)
	st.instruction = strings.Replace(st.instruction, "\t", " ", -1)
	s = strings.TrimSpace(s)

	st.setParams(s)

	// Remove trailing ;
	if len(st.params) > 0 {
		st.params[len(st.params)-1] = strings.TrimSuffix(st.params[len(st.params)-1], ";")
	} else {
		st.instruction = strings.TrimSuffix(st.instruction, ";")
	}

	// Register line continuations.
	if len(st.params) > 0 {
		p := st.params[len(st.params)-1]
		if st.willContinue() {
			p = strings.TrimSuffix(st.params[len(st.params)-1], `\`)
			p = strings.TrimSpace(p)
			if len(p) > 0 {
				st.params[len(st.params)-1] = p
			} else {
				st.params = st.params[:len(st.params)-1]
			}
			st.continued = true
		}
	}
	if strings.HasSuffix(st.instruction, `\`) && !st.contComment {
		i := strings.TrimSuffix(st.instruction, `\`)
		st.instruction = strings.TrimSpace(i)
		st.continued = true
	}

	if len(st.params) == 0 && !st.isLabel() {
		st.function = true
	}

	return &st
}

// setParams will add the string given as parameters.
// Inline comments are retained.
// There will be a space after ",", unless inside a comment.
// A tab is replaced by a space for consistent indentation.
func (st *statement) setParams(s string) {
	st.params = make([]string, 0)
	runes := []rune(s)
	last := '\n'
	inComment := false
	out := make([]rune, 0, len(runes))
	for _, r := range runes {
		switch r {
		case ',':
			if inComment {
				break
			}
			c := strings.TrimSpace(string(out))
			if len(c) > 0 {
				st.params = append(st.params, c)
			}
			out = out[0:0]
			continue
		case '/':
			if last == '*' && inComment {
				inComment = false
			}
		case '*':
			if last == '/' {
				inComment = true
			}
		case '\t':
			if !st.isPreProcessor() {
				r = ' '
			}
		case ';':
			if !inComment {
				out = []rune(strings.TrimSpace(string(out)) + "; ")
				last = r
				continue
			}
		}
		if last == ';' && unicode.IsSpace(r) {
			continue
		}
		last = r
		out = append(out, r)
	}
	c := strings.TrimSpace(string(out))
	if len(c) > 0 {
		st.params = append(st.params, c)
	}
}

// Return true if this line should be at indentation level 0.
func (st statement) level0() bool {
	return st.isLabel() || st.isTEXT() || st.isPreProcessor()
}

// Will return true if the statement is a label.
func (st statement) isLabel() bool {
	return strings.HasSuffix(st.instruction, ":")
}

// isPreProcessor will return if the statement is a preprocessor statement.
func (st statement) isPreProcessor() bool {
	return strings.HasPrefix(st.instruction, "#")
}

// isGlobal returns true if the current instruction is
// a global. Currently that is DATA, GLOBL, FUNCDATA and PCDATA
func (st statement) isGlobal() bool {
	up := strings.ToUpper(st.instruction)
	switch up {
	case "DATA", "GLOBL", "FUNCDATA", "PCDATA":
		return true
	default:
		return false
	}
}

// isTEXT returns true if the instruction is "TEXT"
// or one of the "isGlobal" types
func (st statement) isTEXT() bool {
	up := strings.ToUpper(st.instruction)
	return up == "TEXT" || st.isGlobal()
}

// We attempt to identify "terminators", after which
// indentation is likely to be level 0.
func (st statement) isTerminator() bool {
	up := strings.ToUpper(st.instruction)
	return up == "RET" || up == "JMP"
}

// Detects commands based on case.
func (st statement) isCommand() bool {
	if st.isLabel() {
		return false
	}
	up := strings.ToUpper(st.instruction)
	return up == st.instruction
}

// Detect if last character is '\', indicating a multiline statement.
func (st statement) willContinue() bool {
	if st.continued {
		return true
	}
	if len(st.params) == 0 {
		return false
	}
	return strings.HasSuffix(st.params[len(st.params)-1], `\`)
}

// define returns the macro defined in this line.
// if none is defined "" is returned.
func (st statement) define() string {
	if st.instruction == "#define" && len(st.params) > 0 {
		r := strings.TrimSpace(strings.Split(st.params[0], "(")[0])
		r = strings.Trim(r, `\`)
		return r
	}
	return ""
}

func (st *statement) cleanParams() {
	// Remove whitespace before semicolons
	if strings.HasSuffix(st.instruction, ";") {
		s := strings.TrimSuffix(st.instruction, ";")
		st.instruction = strings.TrimSpace(s) + ";"
	}
}

// formatStatements will format a slice of statements and return each line
// as a separate string.
// Comments and line-continuation (\) are aligned with spaces.
func formatStatements(s []statement) []string {
	res := make([]string, len(s))
	maxParam := 0 // Length of longest parameter
	maxInstr := 0 // Length of longest instruction WITH parameters.
	maxAlone := 0 // Length of longest instruction without parameters.
	for i, x := range s {
		// Clean up and store
		x.cleanParams()
		s[i] = x

		il := len([]rune(x.instruction)) + 1 // Instruction length
		l := il
		// Ignore length if we are a define "function"
		// or we are a parameterless instruction.
		if l > maxInstr && !x.function && !(x.isCommand() && len(x.params) == 0) {
			maxInstr = l
		}
		if x.function && il > maxAlone {
			maxAlone = il
		}
		if len(x.params) > 1 {
			l = 2 * (len(x.params) - 1) // Spaces between parameters
		} else {
			l = 0
		}
		// Add parameters
		for _, y := range x.params {
			l += len([]rune(y))
		}
		l++
		if l > maxParam {
			maxParam = l
		}
	}

	maxParam += maxInstr
	if maxInstr == 0 {
		maxInstr = maxAlone
	}

	for i, x := range s {
		r := x.instruction
		if x.contComment {
			res[i] = x.instruction
			continue
		}
		p := strings.Join(x.params, ", ")
		if len(x.params) > 0 || len(x.comment) > 0 {
			for len(r) < maxInstr {
				r += " "
			}
		}
		r = r + p
		if len(x.comment) > 0 && !x.continued {
			it := maxParam - len([]rune(r))
			for i := 0; i < it; i++ {
				r = r + " "
			}
			r += fmt.Sprintf("// %s", x.comment)
		}

		if x.continued {
			// Find continuation placement.
			it := maxParam - len([]rune(r))
			if maxAlone > maxParam {
				it = maxAlone - len([]rune(r))
			}
			for i := 0; i < it; i++ {
				r = r + " "
			}
			r += `\`
			// Add comment, if any.
			if len(x.comment) > 0 {
				r += " // " + x.comment
			}
		}
		res[i] = r
	}
	return res
}

"""



```