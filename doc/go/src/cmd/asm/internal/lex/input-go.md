Response: Let's break down the thought process for analyzing the `input.go` file.

1. **Understand the Goal:** The primary request is to understand the *functionality* of this Go code snippet, especially concerning pre-processing and macro handling in an assembler. The user also wants Go code examples, command-line interaction details, and potential pitfalls.

2. **Identify Key Data Structures:** The first step is to look at the `Input` struct:

   ```go
   type Input struct {
       Stack
       includes        []string
       beginningOfLine bool
       ifdefStack      []bool
       macros          map[string]*Macro
       text            string // Text of last token returned by Next.
       peek            bool
       peekToken       ScanToken
       peekText        string
   }
   ```

   * `Stack`:  Immediately suggests a way to manage nested input sources (files, macro expansions).
   * `includes`:  Clearly related to `#include` directives.
   * `beginningOfLine`:  Important for directives that must start at the beginning of a line (like `#`).
   * `ifdefStack`:  Manages the state of `#ifdef`/`#ifndef`/`#else`/`#endif` blocks.
   * `macros`: Stores defined macros. This is a central part of the file's purpose.
   * `text`, `peek`, `peekToken`, `peekText`: Indicate a mechanism for looking ahead at tokens.

3. **Analyze Key Methods:**  Next, examine the important methods of the `Input` struct:

   * `NewInput()`:  Initialization, sets up include paths and pre-defined macros from flags.
   * `Next()`: The core tokenization logic, including handling preprocessor directives and macro expansion.
   * `hash()`:  Processes `#` directives.
   * `define()`, `defineMacro()`, `macroDefinition()`:  Handle `#define`.
   * `invokeMacro()`, `argsFor()`, `collectArgument()`: Manage macro invocation and argument parsing.
   * `ifdef()`, `else_()`, `endif()`: Implement conditional compilation.
   * `include()`:  Handles `#include`.
   * `line()`: Processes `#line` directives for debugging information.
   * `undef()`: Handles `#undef`.
   * `Push()`:  Manages the input stack.

4. **Connect Methods to Functionality:** Start mapping the methods to the overall goal:

   * `NewInput` sets up the initial state for processing an assembly file. The `-I` and `-D` flags are clearly relevant here.
   * `Next` is the main loop that gets the next meaningful token, handling preprocessing steps along the way.
   * The `#` processing methods (`hash`, `define`, `include`, `ifdef`, etc.) directly implement the assembler's preprocessor.
   * The macro-related methods (`define...`, `invokeMacro...`) are crucial for macro expansion.

5. **Infer Go Language Feature:**  The extensive handling of `#define` and macro substitution strongly points to the implementation of a **preprocessor**, similar to the C preprocessor but tailored for assembly language.

6. **Develop Go Code Examples:**  Create examples to illustrate the identified functionality.

   * **Macro Definition and Expansion:**  A simple example demonstrating `#define` and its usage. Include an example with arguments.
   * **Conditional Compilation:**  Show how `#ifdef`, `#ifndef`, `#else`, and `#endif` work.
   * **Include Directive:** Demonstrate how `#include` brings in other files.
   * **Predefined Macros:**  Show how `-D` flags define macros on the command line.

7. **Explain Command-Line Parameters:**  Focus on the `-I` and `-D` flags. Explain their purpose and how they affect the `Input` struct.

8. **Identify Common Mistakes:** Think about potential errors a user might make:

   * Incorrect syntax in `#define`.
   * Mismatched `#ifdef`/`#ifndef`/`#else`/`#endif`.
   * Recursive macro definitions (though the code has a safeguard).
   * Incorrect `#include` paths.
   * Forgetting the newline requirement after directives.

9. **Structure the Answer:** Organize the information logically:

   * Start with a high-level summary of the file's purpose.
   * Detail the specific functionalities.
   * Provide Go code examples for each feature.
   * Explain command-line flag usage.
   * List common errors.

10. **Refine and Review:**  Read through the answer, ensuring accuracy, clarity, and completeness. Make sure the Go code examples are runnable and illustrate the concepts effectively. Check that the explanation of command-line parameters is precise.

This systematic approach, starting with the high-level goal and progressively diving into the code details, helps to create a comprehensive and accurate understanding of the `input.go` file. The focus is not just on listing what the code *does*, but also *why* it does it and how a user would interact with it.
`go/src/cmd/asm/internal/lex/input.go` 文件是 Go 汇编器（`cmd/asm`）中词法分析器（`lex`）的输入处理部分。它的主要功能是：

**核心功能：提供汇编源代码的词法单元（tokens）流，并支持预处理指令。**

更具体地说，它做了以下几件事情：

1. **管理输入源栈 (Input Stack):**
   -  使用 `Stack` 结构来管理多个输入源。这使得它可以处理嵌套的输入，例如通过 `#include` 指令包含其他文件。
   -  每次调用 `Next()` 方法时，它会从当前栈顶的输入源读取下一个词法单元。当当前输入源读取完毕时，它会弹出栈顶，切换到前一个输入源。

2. **处理 `#include` 指令:**
   - 当遇到 `#include` 指令时，它会打开指定的文件，并将其作为一个新的输入源压入栈中。
   - 它会按照一定的规则查找被包含的文件，首先在包含当前文件的目录中查找，然后在通过命令行 `-I` 参数指定的目录中查找。

3. **处理宏定义 (`#define`) 和宏展开:**
   -  存储和管理通过 `#define` 定义的宏。
   -  当在代码中遇到宏名称时，它会将宏定义中的 token 替换到输入流中，实现宏展开。
   -  支持带参数的宏定义和展开。

4. **处理条件编译指令 (`#ifdef`, `#ifndef`, `#else`, `#endif`):**
   -  维护一个 `ifdefStack` 来跟踪条件编译的状态。
   -  根据宏是否被定义来决定是否启用（解析）或禁用（跳过）代码块。

5. **处理 `#line` 指令:**
   -  允许在汇编代码中显式指定行号和文件名，这通常用于代码生成器生成的汇编代码，以便在错误报告中提供更准确的源位置信息。

6. **处理 `#undef` 指令:**
   -  允许取消已定义的宏。

7. **处理命令行定义的宏 (`-D` flag):**
   -  在初始化时，会解析命令行 `-D` 参数，并将定义的宏添加到内部的宏表中。

8. **错误处理:**
   -  提供了 `Error` 和 `expectText` 方法用于报告词法分析过程中的错误，并提供错误发生的行号和文件名。

**它是什么 Go 语言功能的实现？**

这个文件实现了一个**简化的 C 预处理器**，专门用于处理汇编语言源代码。虽然它不是完全兼容 C 预处理器，但它实现了最常用的功能，例如文件包含、宏定义和条件编译。

**Go 代码举例说明:**

假设我们有以下汇编源代码文件 `test.s`:

```assembly
#define MSG "Hello, world!"

DATA     Duval+0(SB)/8, $"MSG"

#ifdef DEBUG
    MOVB $1, R0
#endif

TEXT    main(SB),NOSPLIT,$0
    MOVD    (R1), R2
    CALL    runtime·printstring(SB)
    RET
```

并且我们使用以下命令行编译：

```bash
go tool asm -DDEBUG test.s
```

**假设的输入与输出:**

**输入 (来自 `test.s`):**

```assembly
#define MSG "Hello, world!"

DATA    Duval+0(SB)/8, $"MSG"

#ifdef DEBUG
    MOVB $1, R0
#endif

TEXT    main(SB),NOSPLIT,$0
    MOVD    (R1), R2
    CALL    runtime·printstring(SB)
    RET
```

**处理过程 (`input.go` 的部分逻辑):**

1. **`NewInput("test.s")`:** 创建 `Input` 实例，包含 `test.s` 的 `Tokenizer`，并解析 `-DDEBUG`，将 `DEBUG` 宏定义为 `1`。
2. **`Next()`:**
   - 读取 `#define MSG "Hello, world!"`，调用 `define()`，将宏 `MSG` 定义为 `"Hello, world!"` 的 tokens。
   - 读取空行。
   - 读取 `DATA    Duval+0(SB)/8, $"MSG"`。当遇到 `MSG` 时，发现是宏，调用 `invokeMacro()`，将 `$"MSG"` 替换为 `$"Hello, world!"`。实际返回的 token 是 `scanner.String`，其文本为 `"Hello, world!"`。
   - 读取 `#ifdef DEBUG`，由于 `DEBUG` 宏已定义，`ifdefStack` 推入 `true`。
   - 读取 `MOVB $1, R0`，因为 `ifdefStack` 顶端为 `true`，所以返回这些 tokens。
   - 读取 `#endif`，`ifdefStack` 弹出。
   - 继续读取剩余的代码。

**输出 (`Next()` 方法返回的 tokens 流，以及 `Text()` 方法返回的文本):**

| 调用 `Next()` | 返回的 `ScanToken` | `Text()` 返回值          |
|-------------|--------------------|-------------------------|
| 1           | `#`                | `#`                     |
| 2           | `scanner.Ident`    | `define`                |
| 3           | `scanner.Ident`    | `MSG`                   |
| 4           | `scanner.String`   | `"Hello, world!"`       |
| 5           | `\n`               | `\n`                    |
| 6           | `scanner.Ident`    | `DATA`                  |
| 7           | `scanner.Ident`    | `Duval`                 |
| ...         | ...                | ...                     |
| ...         | `scanner.String`   | `"Hello, world!"`       |  // 宏展开的结果
| ...         | ...                | ...                     |
| ...         | `scanner.Ident`    | `MOVB`                  |  // 因为 DEBUG 被定义
| ...         | ...                | ...                     |
| ...         | `scanner.Ident`    | `TEXT`                  |
| ...         | ...                | ...                     |

如果我们将命令行改为 `go tool asm test.s` (不带 `-DDEBUG`)，那么在处理 `#ifdef DEBUG` 时，由于 `DEBUG` 未定义，`ifdefStack` 将推入 `false`，后续的 `MOVB $1, R0` 将会被跳过，`Next()` 不会返回这些 tokens。

**命令行参数的具体处理:**

`input.go` 主要处理以下命令行参数：

- **`-I <目录>`:**  指定头文件（或包含文件）的搜索路径。可以指定多个 `-I` 参数。`NewInput` 函数会将当前文件所在的目录以及所有 `-I` 指定的目录添加到 `includes` 切片中。当遇到 `#include` 指令时，会按照 `includes` 中目录的顺序查找要包含的文件。

- **`-D <宏定义>`:**  定义一个宏。可以指定多个 `-D` 参数。
    - 如果只指定宏名，例如 `-DDEBUG`，则宏的值默认为 `"1"`。
    - 如果指定宏名和值，例如 `-DVERSION="1.0"`，则宏的值为指定的值。
    - `predefine` 函数会解析这些 `-D` 参数，并将定义的宏添加到 `macros` map 中。如果定义的不是有效的标识符，会报错并退出。

**使用者易犯错的点:**

1. **`#define` 语法错误:**
   - 宏名称必须是合法的标识符。
   - 定义带参数的宏时，括号必须紧跟宏名称，不能有空格，例如 `#define FUNC(x)` 是正确的，而 `#define FUNC (x)` 会被解析为不带参数的宏。
   - 宏定义中，反斜杠 `\` 只能用于转义换行符或另一个反斜杠。

   ```go
   // 错误示例：宏名包含空格
   // #define MY MACRO 1 // 编译时会报错

   // 错误示例：带参数的宏定义括号前有空格
   // #define FUNC (x) x*x

   // 错误示例：反斜杠转义了其他字符
   // #define PATH /a\b/c
   ```

2. **条件编译指令不匹配:**
   -  `#ifdef` 和 `#ifndef` 必须与 `#endif` 配对使用。
   -  `#else` 只能在 `#ifdef` 或 `#ifndef` 和 `#endif` 之间使用。

   ```assembly
   // 错误示例：缺少 #endif
   //#ifdef DEBUG
   //  MOVB $1, R0

   // 错误示例：多余的 #else
   //#else
   //  MOVB $0, R0
   ```

3. **`#include` 文件路径错误:**
   -  指定的文件不存在于当前目录或 `-I` 指定的路径中。

   ```assembly
   //#include "non_existent_file.s" // 如果文件不存在，编译时会报错
   ```

4. **宏的递归调用:**
   -  定义了会无限循环展开的宏。`Input` 中有机制防止无限递归，超过一定嵌套深度会报错。

   ```assembly
   //#define A B
   //#define B A
   //
   // DATA symbol+0(SB)/8, $A  // 会导致递归调用错误
   ```

5. **在 `#` 后面的指令名称拼写错误:**
   -  如果 `#` 后面跟着的不是预期的指令名称（`define`, `include`, `ifdef` 等），会报错。

   ```assembly
   //#defne MSG "error" // 拼写错误
   ```

理解 `input.go` 的功能对于理解 Go 汇编器如何处理源代码至关重要。它负责将原始的汇编代码转化为可以被后续阶段处理的 token 流，并提供了预处理能力，使得汇编代码的编写更加灵活和可维护。

Prompt: 
```
这是路径为go/src/cmd/asm/internal/lex/input.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lex

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/scanner"

	"cmd/asm/internal/flags"
	"cmd/internal/objabi"
	"cmd/internal/src"
)

// Input is the main input: a stack of readers and some macro definitions.
// It also handles #include processing (by pushing onto the input stack)
// and parses and instantiates macro definitions.
type Input struct {
	Stack
	includes        []string
	beginningOfLine bool
	ifdefStack      []bool
	macros          map[string]*Macro
	text            string // Text of last token returned by Next.
	peek            bool
	peekToken       ScanToken
	peekText        string
}

// NewInput returns an Input from the given path.
func NewInput(name string) *Input {
	return &Input{
		// include directories: look in source dir, then -I directories.
		includes:        append([]string{filepath.Dir(name)}, flags.I...),
		beginningOfLine: true,
		macros:          predefine(flags.D),
	}
}

// predefine installs the macros set by the -D flag on the command line.
func predefine(defines flags.MultiFlag) map[string]*Macro {
	macros := make(map[string]*Macro)
	for _, name := range defines {
		value := "1"
		i := strings.IndexRune(name, '=')
		if i > 0 {
			name, value = name[:i], name[i+1:]
		}
		tokens := Tokenize(name)
		if len(tokens) != 1 || tokens[0].ScanToken != scanner.Ident {
			fmt.Fprintf(os.Stderr, "asm: parsing -D: %q is not a valid identifier name\n", tokens[0])
			flags.Usage()
		}
		macros[name] = &Macro{
			name:   name,
			args:   nil,
			tokens: Tokenize(value),
		}
	}
	return macros
}

var panicOnError bool // For testing.

func (in *Input) Error(args ...interface{}) {
	if panicOnError {
		panic(fmt.Errorf("%s:%d: %s", in.File(), in.Line(), fmt.Sprintln(args...)))
	}
	fmt.Fprintf(os.Stderr, "%s:%d: %s", in.File(), in.Line(), fmt.Sprintln(args...))
	os.Exit(1)
}

// expectText is like Error but adds "got XXX" where XXX is a quoted representation of the most recent token.
func (in *Input) expectText(args ...interface{}) {
	in.Error(append(args, "; got", strconv.Quote(in.Stack.Text()))...)
}

// enabled reports whether the input is enabled by an ifdef, or is at the top level.
func (in *Input) enabled() bool {
	return len(in.ifdefStack) == 0 || in.ifdefStack[len(in.ifdefStack)-1]
}

func (in *Input) expectNewline(directive string) {
	tok := in.Stack.Next()
	if tok != '\n' {
		in.expectText("expected newline after", directive)
	}
}

func (in *Input) Next() ScanToken {
	if in.peek {
		in.peek = false
		tok := in.peekToken
		in.text = in.peekText
		return tok
	}
	// If we cannot generate a token after 100 macro invocations, we're in trouble.
	// The usual case is caught by Push, below, but be safe.
	for nesting := 0; nesting < 100; {
		tok := in.Stack.Next()
		switch tok {
		case '#':
			if !in.beginningOfLine {
				in.Error("'#' must be first item on line")
			}
			in.beginningOfLine = in.hash()
			in.text = "#"
			return '#'

		case scanner.Ident:
			// Is it a macro name?
			name := in.Stack.Text()
			macro := in.macros[name]
			if macro != nil {
				nesting++
				in.invokeMacro(macro)
				continue
			}
			fallthrough
		default:
			if tok == scanner.EOF && len(in.ifdefStack) > 0 {
				// We're skipping text but have run out of input with no #endif.
				in.Error("unclosed #ifdef or #ifndef")
			}
			in.beginningOfLine = tok == '\n'
			if in.enabled() {
				in.text = in.Stack.Text()
				return tok
			}
		}
	}
	in.Error("recursive macro invocation")
	return 0
}

func (in *Input) Text() string {
	return in.text
}

// hash processes a # preprocessor directive. It reports whether it completes.
func (in *Input) hash() bool {
	// We have a '#'; it must be followed by a known word (define, include, etc.).
	tok := in.Stack.Next()
	if tok != scanner.Ident {
		in.expectText("expected identifier after '#'")
	}
	if !in.enabled() {
		// Can only start including again if we are at #else or #endif but also
		// need to keep track of nested #if[n]defs.
		// We let #line through because it might affect errors.
		switch in.Stack.Text() {
		case "else", "endif", "ifdef", "ifndef", "line":
			// Press on.
		default:
			return false
		}
	}
	switch in.Stack.Text() {
	case "define":
		in.define()
	case "else":
		in.else_()
	case "endif":
		in.endif()
	case "ifdef":
		in.ifdef(true)
	case "ifndef":
		in.ifdef(false)
	case "include":
		in.include()
	case "line":
		in.line()
	case "undef":
		in.undef()
	default:
		in.Error("unexpected token after '#':", in.Stack.Text())
	}
	return true
}

// macroName returns the name for the macro being referenced.
func (in *Input) macroName() string {
	// We use the Stack's input method; no macro processing at this stage.
	tok := in.Stack.Next()
	if tok != scanner.Ident {
		in.expectText("expected identifier after # directive")
	}
	// Name is alphanumeric by definition.
	return in.Stack.Text()
}

// #define processing.
func (in *Input) define() {
	name := in.macroName()
	args, tokens := in.macroDefinition(name)
	in.defineMacro(name, args, tokens)
}

// defineMacro stores the macro definition in the Input.
func (in *Input) defineMacro(name string, args []string, tokens []Token) {
	if in.macros[name] != nil {
		in.Error("redefinition of macro:", name)
	}
	in.macros[name] = &Macro{
		name:   name,
		args:   args,
		tokens: tokens,
	}
}

// macroDefinition returns the list of formals and the tokens of the definition.
// The argument list is nil for no parens on the definition; otherwise a list of
// formal argument names.
func (in *Input) macroDefinition(name string) ([]string, []Token) {
	prevCol := in.Stack.Col()
	tok := in.Stack.Next()
	if tok == '\n' || tok == scanner.EOF {
		return nil, nil // No definition for macro
	}
	var args []string
	// The C preprocessor treats
	//	#define A(x)
	// and
	//	#define A (x)
	// distinctly: the first is a macro with arguments, the second without.
	// Distinguish these cases using the column number, since we don't
	// see the space itself. Note that text/scanner reports the position at the
	// end of the token. It's where you are now, and you just read this token.
	if tok == '(' && in.Stack.Col() == prevCol+1 {
		// Macro has arguments. Scan list of formals.
		acceptArg := true
		args = []string{} // Zero length but not nil.
	Loop:
		for {
			tok = in.Stack.Next()
			switch tok {
			case ')':
				tok = in.Stack.Next() // First token of macro definition.
				break Loop
			case ',':
				if acceptArg {
					in.Error("bad syntax in definition for macro:", name)
				}
				acceptArg = true
			case scanner.Ident:
				if !acceptArg {
					in.Error("bad syntax in definition for macro:", name)
				}
				arg := in.Stack.Text()
				if slices.Contains(args, arg) {
					in.Error("duplicate argument", arg, "in definition for macro:", name)
				}
				args = append(args, arg)
				acceptArg = false
			default:
				in.Error("bad definition for macro:", name)
			}
		}
	}
	var tokens []Token
	// Scan to newline. Backslashes escape newlines.
	for tok != '\n' {
		if tok == scanner.EOF {
			in.Error("missing newline in definition for macro:", name)
		}
		if tok == '\\' {
			tok = in.Stack.Next()
			if tok != '\n' && tok != '\\' {
				in.Error(`can only escape \ or \n in definition for macro:`, name)
			}
		}
		tokens = append(tokens, Make(tok, in.Stack.Text()))
		tok = in.Stack.Next()
	}
	return args, tokens
}

// invokeMacro pushes onto the input Stack a Slice that holds the macro definition with the actual
// parameters substituted for the formals.
// Invoking a macro does not touch the PC/line history.
func (in *Input) invokeMacro(macro *Macro) {
	// If the macro has no arguments, just substitute the text.
	if macro.args == nil {
		in.Push(NewSlice(in.Base(), in.Line(), macro.tokens))
		return
	}
	tok := in.Stack.Next()
	if tok != '(' {
		// If the macro has arguments but is invoked without them, all we push is the macro name.
		// First, put back the token.
		in.peekToken = tok
		in.peekText = in.text
		in.peek = true
		in.Push(NewSlice(in.Base(), in.Line(), []Token{Make(macroName, macro.name)}))
		return
	}
	actuals := in.argsFor(macro)
	var tokens []Token
	for _, tok := range macro.tokens {
		if tok.ScanToken != scanner.Ident {
			tokens = append(tokens, tok)
			continue
		}
		substitution := actuals[tok.text]
		if substitution == nil {
			tokens = append(tokens, tok)
			continue
		}
		tokens = append(tokens, substitution...)
	}
	in.Push(NewSlice(in.Base(), in.Line(), tokens))
}

// argsFor returns a map from formal name to actual value for this argumented macro invocation.
// The opening parenthesis has been absorbed.
func (in *Input) argsFor(macro *Macro) map[string][]Token {
	var args [][]Token
	// One macro argument per iteration. Collect them all and check counts afterwards.
	for argNum := 0; ; argNum++ {
		tokens, tok := in.collectArgument(macro)
		args = append(args, tokens)
		if tok == ')' {
			break
		}
	}
	// Zero-argument macros are tricky.
	if len(macro.args) == 0 && len(args) == 1 && args[0] == nil {
		args = nil
	} else if len(args) != len(macro.args) {
		in.Error("wrong arg count for macro", macro.name)
	}
	argMap := make(map[string][]Token)
	for i, arg := range args {
		argMap[macro.args[i]] = arg
	}
	return argMap
}

// collectArgument returns the actual tokens for a single argument of a macro.
// It also returns the token that terminated the argument, which will always
// be either ',' or ')'. The starting '(' has been scanned.
func (in *Input) collectArgument(macro *Macro) ([]Token, ScanToken) {
	nesting := 0
	var tokens []Token
	for {
		tok := in.Stack.Next()
		if tok == scanner.EOF || tok == '\n' {
			in.Error("unterminated arg list invoking macro:", macro.name)
		}
		if nesting == 0 && (tok == ')' || tok == ',') {
			return tokens, tok
		}
		if tok == '(' {
			nesting++
		}
		if tok == ')' {
			nesting--
		}
		tokens = append(tokens, Make(tok, in.Stack.Text()))
	}
}

// #ifdef and #ifndef processing.
func (in *Input) ifdef(truth bool) {
	name := in.macroName()
	in.expectNewline("#if[n]def")
	if !in.enabled() {
		truth = false
	} else if _, defined := in.macros[name]; !defined {
		truth = !truth
	}
	in.ifdefStack = append(in.ifdefStack, truth)
}

// #else processing
func (in *Input) else_() {
	in.expectNewline("#else")
	if len(in.ifdefStack) == 0 {
		in.Error("unmatched #else")
	}
	if len(in.ifdefStack) == 1 || in.ifdefStack[len(in.ifdefStack)-2] {
		in.ifdefStack[len(in.ifdefStack)-1] = !in.ifdefStack[len(in.ifdefStack)-1]
	}
}

// #endif processing.
func (in *Input) endif() {
	in.expectNewline("#endif")
	if len(in.ifdefStack) == 0 {
		in.Error("unmatched #endif")
	}
	in.ifdefStack = in.ifdefStack[:len(in.ifdefStack)-1]
}

// #include processing.
func (in *Input) include() {
	// Find and parse string.
	tok := in.Stack.Next()
	if tok != scanner.String {
		in.expectText("expected string after #include")
	}
	name, err := strconv.Unquote(in.Stack.Text())
	if err != nil {
		in.Error("unquoting include file name: ", err)
	}
	in.expectNewline("#include")
	// Push tokenizer for file onto stack.
	fd, err := os.Open(name)
	if err != nil {
		for _, dir := range in.includes {
			fd, err = os.Open(filepath.Join(dir, name))
			if err == nil {
				break
			}
		}
		if err != nil {
			in.Error("#include:", err)
		}
	}
	in.Push(NewTokenizer(name, fd, fd))
}

// #line processing.
func (in *Input) line() {
	// Only need to handle Plan 9 format: #line 337 "filename"
	tok := in.Stack.Next()
	if tok != scanner.Int {
		in.expectText("expected line number after #line")
	}
	line, err := strconv.Atoi(in.Stack.Text())
	if err != nil {
		in.Error("error parsing #line (cannot happen):", err)
	}
	tok = in.Stack.Next()
	if tok != scanner.String {
		in.expectText("expected file name in #line")
	}
	file, err := strconv.Unquote(in.Stack.Text())
	if err != nil {
		in.Error("unquoting #line file name: ", err)
	}
	tok = in.Stack.Next()
	if tok != '\n' {
		in.Error("unexpected token at end of #line: ", tok)
	}
	pos := src.MakePos(in.Base(), uint(in.Line())+1, 1) // +1 because #line nnn means line nnn starts on next line
	in.Stack.SetBase(src.NewLinePragmaBase(pos, file, objabi.AbsFile(objabi.WorkingDir(), file, *flags.TrimPath), uint(line), 1))
}

// #undef processing
func (in *Input) undef() {
	name := in.macroName()
	if in.macros[name] == nil {
		in.Error("#undef for undefined macro:", name)
	}
	// Newline must be next.
	tok := in.Stack.Next()
	if tok != '\n' {
		in.Error("syntax error in #undef for macro:", name)
	}
	delete(in.macros, name)
}

func (in *Input) Push(r TokenReader) {
	if len(in.tr) > 100 {
		in.Error("input recursion")
	}
	in.Stack.Push(r)
}

func (in *Input) Close() {
}

"""



```