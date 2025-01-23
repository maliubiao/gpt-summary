Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The code is in a file named `endtoend_test.go` within the `cmd/asm/internal/asm` package. The comment at the beginning states "An end-to-end test for the assembler: Do we print what we parse?" This immediately tells us it's testing the assembler's output against expected output.

2. **Understand the Test Structure:** The code defines two primary testing functions: `testEndToEnd` and `testErrors`. This suggests two main categories of tests: successful assembly and error handling.

3. **Deep Dive into `testEndToEnd`:**

   * **Input:** The function takes `t *testing.T`, `goarch` (target architecture), and `file` (base filename of the assembly source).
   * **File Loading and Initialization:**  It constructs the input filename, sets up the architecture using `setArch`, initializes the architecture, and creates a lexer and parser. This is standard for compiler/assembler testing.
   * **Output Capture:**  `testOut = new(strings.Builder)` suggests it's capturing the assembler's standard output. The lines related to `ctxt.Bso` confirm this, as `ctxt.Bso` is typically used for buffered output, and it's being flushed at the end.
   * **Error Handling during Assembly:** `ctxt.DiagFunc` is overridden to capture assembler diagnostics (errors). This is crucial for determining if the assembly process succeeded.
   * **Parsing and Assembly:** `parser.Parse()` is the core assembly step.
   * **Golden File Comparison:** The code then reads the input file again and attempts to "parse" it in a simplified way to reconstruct the expected output. This involves splitting lines, ignoring comments and specific directives (like `GLOBL`), and formatting the expected output.
   * **Output Matching:** The `want` variable represents the expected output for a line, and the code iterates through the actual output (`output`) comparing it against the expected output. This is the heart of the end-to-end test.
   * **Hex Encoding Verification:**  The code also looks for hex encodings within comments (`// hex encoding`) and compares these against the actual generated machine code (`text.P`). This ensures the assembler is generating the correct byte sequences.
   * **Key Data Structures:** `hexByLine` is used to store the expected hex encoding for each line, allowing for deferred comparison after assembly.

4. **Deep Dive into `testErrors`:**

   * **Similar Setup:** This function also takes `t *testing.T`, `goarch`, and `file`, and performs similar initialization steps as `testEndToEnd`.
   * **Error Capture:** Instead of capturing standard output, this function focuses on capturing error messages using a `bytes.Buffer` (`errBuf`) and overriding `ctxt.DiagFunc` to write to it.
   * **Expected Error Parsing:** It reads the input file and looks for lines starting with `// ERROR ` to extract the expected error messages.
   * **Error Matching:** It compares the captured error messages against the expected ones, checking for both presence and content. Regular expressions are used to extract the relevant information.
   * **Flags:** The `flags` parameter allows for setting specific assembler flags, like `dynlink`.

5. **Identify Supporting Functions:**

   * `isHexes`:  A utility function to check if a string is a valid hexadecimal representation.
   * Regular Expressions (`fileLineRE`, `errRE`, `errQuotesRE`): Used for parsing error messages.

6. **Infer Go Language Features Being Tested:**

   * **Assembly Language Parsing:** The core functionality is parsing assembly language syntax. This involves recognizing instructions, operands, labels, directives, etc.
   * **Code Generation:** The tests verify that the assembler generates the correct machine code (hex encoding).
   * **Error Reporting:** The `testErrors` function specifically tests the assembler's ability to detect and report syntax and semantic errors in the assembly code.
   * **Architecture-Specific Instructions:** The tests are parameterized by `goarch`, suggesting that the assembler needs to handle different instruction sets for different architectures (e.g., 386, ARM, AMD64).
   * **Assembler Directives:** The tests implicitly cover assembler directives like `TEXT`, `GLOBL`, data definitions, etc.

7. **Construct Example:** Based on the understanding of `testEndToEnd`, construct a simple example input and the expected output. Focus on a single instruction to keep it manageable.

8. **Identify Command-Line Arguments:** Look for how the code uses the `flags` parameter in `testErrors`. The example shows the `"dynlink"` flag being used to set `ctxt.Flag_dynlink`.

9. **Identify Potential User Errors:** Think about common mistakes when writing assembly code. The code explicitly ignores `GLOBL` directives in the output comparison, hinting that discrepancies in `GLOBL` output might be a source of confusion. Also, incorrect hex encodings in the test files themselves could lead to errors.

10. **Review and Refine:**  Read through the analysis, ensuring clarity and accuracy. Check for any missing pieces or inconsistencies. For example, initially, I might have overlooked the significance of `ctxt.Bso`, but realizing it's used for output buffering clarifies how the output is captured.

This iterative process of understanding the code's structure, purpose, and interactions allows for a comprehensive analysis and the ability to answer the specific questions in the prompt.
这段代码是Go语言 `cmd/asm` 包中用于进行**端到端（end-to-end）测试**的一部分。它的主要功能是：

1. **测试汇编器是否能正确解析汇编代码并生成预期的输出。** 它通过比较汇编器对输入文件生成的文本输出和预期的输出（通常在输入文件中以注释形式给出）来验证汇编器的解析和打印功能。
2. **测试汇编器生成的机器码是否与预期一致。** 它会读取输入文件中指定的十六进制机器码，并与汇编器实际生成的机器码进行比较。
3. **测试汇编器能否正确地报告错误。**  通过 `testErrors` 函数，它可以测试汇编器在遇到错误的汇编代码时是否能产生预期的错误信息。

**以下是更详细的分解：**

**1. `testEndToEnd(t *testing.T, goarch, file string)` 函数：**

* **功能：**  对指定的架构 (`goarch`) 和汇编文件 (`file`) 执行端到端测试。
* **工作流程：**
    * **加载输入文件：** 从 `testdata` 目录下加载名为 `file.s` 的汇编源文件。
    * **设置架构：** 调用 `setArch(goarch)` 设置目标架构，并初始化上下文 (`ctxt`)。
    * **词法分析和语法分析：** 创建词法分析器 (`lex.NewLexer`) 和语法分析器 (`NewParser`) 来解析汇编代码。
    * **捕获汇编器输出：**  创建 `strings.Builder` 类型的 `testOut` 变量，汇编器会将生成的文本输出写入这个缓冲区。
    * **设置错误处理：** 重写 `ctxt.DiagFunc`，以便在汇编过程中发生错误时，将错误信息记录下来并标记测试失败。
    * **执行汇编：** 调用 `parser.Parse()` 开始解析汇编代码。
    * **比较文本输出：**
        * 读取输入文件内容，并“手动”解析每一行，提取预期的汇编输出和机器码（通过注释 `// printed form` 和 `// hex encoding`）。
        * 将汇编器的实际输出 (`testOut.String()`) 与预期的输出进行逐行比较。
        * 会对输出进行规范化处理，例如统一空格和处理相对跳转地址。
    * **比较机器码：**
        * 遍历汇编器生成的指令列表 (`pList.Firstpc`)。
        * 从输入文件的注释中提取预期的十六进制机器码。
        * 将实际生成的机器码 (`text.P`) 与预期进行比较。
    * **报告错误：** 如果实际输出与预期不符，或者生成的机器码与预期不符，则使用 `t.Errorf` 报告错误。

**Go 代码示例 (说明 `testEndToEnd` 如何工作)：**

假设 `testdata/example.s` 文件内容如下 (针对 amd64 架构)：

```assembly
// MOVQ $1, AX // MOVQ $0x1, AX // 48 c7 c0 01 00 00 00
MOVQ $1, AX
```

`testEndToEnd(t, "amd64", "example")` 的执行过程大致如下：

1. 加载 `testdata/example.s`。
2. 设置 `goarch` 为 `amd64`。
3. 汇编器解析 `MOVQ $1, AX`。
4. 汇编器将生成类似如下的输出并写入 `testOut`：
   ```
   00001 (testdata/example.s:2)	MOVQ	$1, AX
   ```
5. 代码读取 `testdata/example.s`，解析第二行，提取预期的输出 `MOVQ $0x1, AX` 和机器码 `48 c7 c0 01 00 00 00`。
6. 比较实际输出和预期输出（规范化后）：
   * 实际输出: `00001 (testdata/example.s:2)	MOVQ	$1, AX`
   * 预期输出: `00001 (testdata/example.s:2)	MOVQ	$1, AX` (经过空格规范化，`$0x1` 会变成 `$1`)
7. 比较实际机器码和预期机器码：
   * 实际机器码（从汇编器生成）：`48c7c001000000`
   * 预期机器码（从注释中提取）：`48c7c001000000`
8. 如果两者都匹配，则测试通过。

**假设的输入与输出（基于上述示例）：**

**输入 (`testdata/example.s`):**

```assembly
// MOVQ $1, AX // MOVQ $0x1, AX // 48 c7 c0 01 00 00 00
MOVQ $1, AX
```

**预期输出 (根据代码逻辑推断):**

```
00001 (testdata/example.s:2)	MOVQ	$1, AX
```

**实际生成的机器码 (假设):**

`48c7c001000000`

**2. `testErrors(t *testing.T, goarch, file string, flags ...string)` 函数：**

* **功能：** 测试汇编器在遇到错误代码时是否能产生预期的错误信息。
* **工作流程：**
    * 与 `testEndToEnd` 类似，加载输入文件，设置架构等。
    * **捕获错误信息：** 使用 `bytes.Buffer` 类型的 `errBuf` 来捕获汇编器产生的错误信息。重写 `ctxt.DiagFunc` 将错误信息写入 `errBuf`。
    * **处理 flags：** 允许传入一些标志 (`flags`) 来影响汇编过程，例如 `"dynlink"`。
    * **执行汇编：** 调用 `parser.Parse()`。
    * **比较错误信息：**
        * 读取输入文件，查找以 `// ERROR ` 开头的注释，这些注释包含了预期的错误信息。
        * 将汇编器实际产生的错误信息 (`errBuf.String()`) 与预期进行比较。
        * 使用正则表达式 (`fileLineRE`, `errRE`, `errQuotesRE`) 来解析和匹配错误信息。

**Go 代码示例 (说明 `testErrors` 如何工作)：**

假设 `testdata/error.s` 文件内容如下 (针对 amd64 架构)：

```assembly
// ERROR "invalid operation"
INVALIDE INSTRUCTION
```

`testErrors(t, "amd64", "error")` 的执行过程大致如下：

1. 加载 `testdata/error.s`。
2. 设置 `goarch` 为 `amd64`。
3. 汇编器尝试解析 `INVALIDE INSTRUCTION`，会因为指令无效而报错。
4. 汇编器将错误信息（例如 `testdata/error.s:2: invalid operation`）写入 `errBuf`。
5. 代码读取 `testdata/error.s`，找到注释 `// ERROR "invalid operation"`，提取预期的错误信息 `"invalid operation"`。
6. 比较实际错误信息和预期错误信息，确认实际错误信息中包含 `"invalid operation"`。
7. 如果匹配，则测试通过。

**命令行参数的具体处理：**

`testErrors` 函数接受一个可变参数 `flags ...string`。目前的代码中，它只处理了一个标志：

* **`"dynlink"`:**  如果 `flags` 中包含 `"dynlink"`，则会将汇编器上下文的 `ctxt.Flag_dynlink` 设置为 `true`。这会影响汇编器在处理动态链接相关的代码时的行为。

**使用者易犯错的点：**

1. **预期的汇编输出或机器码注释不正确：**  `testEndToEnd` 依赖于输入文件中注释的正确性来判断汇编器的输出是否正确。如果注释中的预期输出或机器码与实际情况不符，会导致测试失败，但实际可能是测试用例错误而不是汇编器错误。
   * **示例：** 在 `testdata/example.s` 中，如果将机器码注释写错，例如 `// 48 c7 c0 00 00 00 00`，即使汇编器生成了正确的机器码，测试也会失败。

2. **错误信息注释不准确或不完整：** `testErrors` 依赖于 `// ERROR` 注释来判断是否产生了预期的错误。如果注释不准确（例如拼写错误）或不够具体，可能导致测试失败或无法覆盖所有可能的错误情况。
   * **示例：** 如果 `testdata/error.s` 中的注释写成 `// ERROR "invalid op"`，即使汇编器报告的错误是 `"invalid operation"`，测试也会失败。

3. **忽略了空格和格式的规范化：** `testEndToEnd` 会对汇编器的输出进行规范化处理，例如统一空格。如果手动编写预期输出时没有考虑到这一点，可能会导致不必要的测试失败。

4. **不理解相对跳转地址的处理：** `testEndToEnd` 会自动将相对跳转地址转换为绝对地址进行比较。如果人为地在注释中写死了相对地址，可能会导致测试失败。

总而言之，这段代码是 Go 汇编器的重要测试组成部分，它通过端到端的方式验证汇编器的核心功能，确保其能够正确解析汇编代码、生成预期的输出和机器码，并能有效地报告错误。编写和维护这些测试用例需要对汇编语言和汇编器的工作原理有深入的理解。

### 提示词
```
这是路径为go/src/cmd/asm/internal/asm/endtoend_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asm

import (
	"bufio"
	"bytes"
	"fmt"
	"internal/buildcfg"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"cmd/asm/internal/lex"
	"cmd/internal/obj"
)

// An end-to-end test for the assembler: Do we print what we parse?
// Output is generated by, in effect, turning on -S and comparing the
// result against a golden file.

func testEndToEnd(t *testing.T, goarch, file string) {
	input := filepath.Join("testdata", file+".s")
	architecture, ctxt := setArch(goarch)
	architecture.Init(ctxt)
	lexer := lex.NewLexer(input)
	parser := NewParser(ctxt, architecture, lexer)
	pList := new(obj.Plist)
	var ok bool
	testOut = new(strings.Builder) // The assembler writes test output to this buffer.
	ctxt.Bso = bufio.NewWriter(os.Stdout)
	ctxt.IsAsm = true
	defer ctxt.Bso.Flush()
	failed := false
	ctxt.DiagFunc = func(format string, args ...interface{}) {
		failed = true
		t.Errorf(format, args...)
	}
	pList.Firstpc, ok = parser.Parse()
	if !ok || failed {
		t.Errorf("asm: %s assembly failed", goarch)
		return
	}
	output := strings.Split(testOut.String(), "\n")

	// Reconstruct expected output by independently "parsing" the input.
	data, err := os.ReadFile(input)
	if err != nil {
		t.Error(err)
		return
	}
	lineno := 0
	seq := 0
	hexByLine := map[string]string{}
	lines := strings.SplitAfter(string(data), "\n")
Diff:
	for _, line := range lines {
		lineno++

		// Ignore include of textflag.h.
		if strings.HasPrefix(line, "#include ") {
			continue
		}

		// Ignore GLOBL.
		if strings.HasPrefix(line, "GLOBL ") {
			continue
		}

		// The general form of a test input line is:
		//	// comment
		//	INST args [// printed form] [// hex encoding]
		parts := strings.Split(line, "//")
		printed := strings.TrimSpace(parts[0])
		if printed == "" || strings.HasSuffix(printed, ":") { // empty or label
			continue
		}
		seq++

		var hexes string
		switch len(parts) {
		default:
			t.Errorf("%s:%d: unable to understand comments: %s", input, lineno, line)
		case 1:
			// no comment
		case 2:
			// might be printed form or hex
			note := strings.TrimSpace(parts[1])
			if isHexes(note) {
				hexes = note
			} else {
				printed = note
			}
		case 3:
			// printed form, then hex
			printed = strings.TrimSpace(parts[1])
			hexes = strings.TrimSpace(parts[2])
			if !isHexes(hexes) {
				t.Errorf("%s:%d: malformed hex instruction encoding: %s", input, lineno, line)
			}
		}

		if hexes != "" {
			hexByLine[fmt.Sprintf("%s:%d", input, lineno)] = hexes
		}

		// Canonicalize spacing in printed form.
		// First field is opcode, then tab, then arguments separated by spaces.
		// Canonicalize spaces after commas first.
		// Comma to separate argument gets a space; comma within does not.
		var buf []byte
		nest := 0
		for i := 0; i < len(printed); i++ {
			c := printed[i]
			switch c {
			case '{', '[':
				nest++
			case '}', ']':
				nest--
			case ',':
				buf = append(buf, ',')
				if nest == 0 {
					buf = append(buf, ' ')
				}
				for i+1 < len(printed) && (printed[i+1] == ' ' || printed[i+1] == '\t') {
					i++
				}
				continue
			}
			buf = append(buf, c)
		}

		f := strings.Fields(string(buf))

		// Turn relative (PC) into absolute (PC) automatically,
		// so that most branch instructions don't need comments
		// giving the absolute form.
		if len(f) > 0 && strings.Contains(printed, "(PC)") {
			index := len(f) - 1
			suf := "(PC)"
			for !strings.HasSuffix(f[index], suf) {
				index--
				suf = "(PC),"
			}
			str := f[index]
			n, err := strconv.Atoi(str[:len(str)-len(suf)])
			if err == nil {
				f[index] = fmt.Sprintf("%d%s", seq+n, suf)
			}
		}

		if len(f) == 1 {
			printed = f[0]
		} else {
			printed = f[0] + "\t" + strings.Join(f[1:], " ")
		}

		want := fmt.Sprintf("%05d (%s:%d)\t%s", seq, input, lineno, printed)
		for len(output) > 0 && (output[0] < want || output[0] != want && len(output[0]) >= 5 && output[0][:5] == want[:5]) {
			if len(output[0]) >= 5 && output[0][:5] == want[:5] {
				t.Errorf("mismatched output:\nhave %s\nwant %s", output[0], want)
				output = output[1:]
				continue Diff
			}
			t.Errorf("unexpected output: %q", output[0])
			output = output[1:]
		}
		if len(output) > 0 && output[0] == want {
			output = output[1:]
		} else {
			t.Errorf("missing output: %q", want)
		}
	}
	for len(output) > 0 {
		if output[0] == "" {
			// spurious blank caused by Split on "\n"
			output = output[1:]
			continue
		}
		t.Errorf("unexpected output: %q", output[0])
		output = output[1:]
	}

	// Checked printing.
	// Now check machine code layout.

	top := pList.Firstpc
	var text *obj.LSym
	ok = true
	ctxt.DiagFunc = func(format string, args ...interface{}) {
		t.Errorf(format, args...)
		ok = false
	}
	obj.Flushplist(ctxt, pList, nil)

	for p := top; p != nil; p = p.Link {
		if p.As == obj.ATEXT {
			text = p.From.Sym
		}
		hexes := hexByLine[p.Line()]
		if hexes == "" {
			continue
		}
		delete(hexByLine, p.Line())
		if text == nil {
			t.Errorf("%s: instruction outside TEXT", p)
		}
		size := int64(len(text.P)) - p.Pc
		if p.Link != nil {
			size = p.Link.Pc - p.Pc
		} else if p.Isize != 0 {
			size = int64(p.Isize)
		}
		var code []byte
		if p.Pc < int64(len(text.P)) {
			code = text.P[p.Pc:]
			if size < int64(len(code)) {
				code = code[:size]
			}
		}
		codeHex := fmt.Sprintf("%x", code)
		if codeHex == "" {
			codeHex = "empty"
		}
		ok := false
		for _, hex := range strings.Split(hexes, " or ") {
			if codeHex == hex {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("%s: have encoding %s, want %s", p, codeHex, hexes)
		}
	}

	if len(hexByLine) > 0 {
		var missing []string
		for key := range hexByLine {
			missing = append(missing, key)
		}
		sort.Strings(missing)
		for _, line := range missing {
			t.Errorf("%s: did not find instruction encoding", line)
		}
	}

}

func isHexes(s string) bool {
	if s == "" {
		return false
	}
	if s == "empty" {
		return true
	}
	for _, f := range strings.Split(s, " or ") {
		if f == "" || len(f)%2 != 0 || strings.TrimLeft(f, "0123456789abcdef") != "" {
			return false
		}
	}
	return true
}

// It would be nice if the error messages always began with
// the standard file:line: prefix,
// but that's not where we are today.
// It might be at the beginning but it might be in the middle of the printed instruction.
var fileLineRE = regexp.MustCompile(`(?:^|\()(testdata[/\\][\da-z]+\.s:\d+)(?:$|\)|:)`)

// Same as in test/run.go
var (
	errRE       = regexp.MustCompile(`// ERROR ?(.*)`)
	errQuotesRE = regexp.MustCompile(`"([^"]*)"`)
)

func testErrors(t *testing.T, goarch, file string, flags ...string) {
	input := filepath.Join("testdata", file+".s")
	architecture, ctxt := setArch(goarch)
	architecture.Init(ctxt)
	lexer := lex.NewLexer(input)
	parser := NewParser(ctxt, architecture, lexer)
	pList := new(obj.Plist)
	var ok bool
	ctxt.Bso = bufio.NewWriter(os.Stdout)
	ctxt.IsAsm = true
	defer ctxt.Bso.Flush()
	failed := false
	var errBuf bytes.Buffer
	parser.errorWriter = &errBuf
	ctxt.DiagFunc = func(format string, args ...interface{}) {
		failed = true
		s := fmt.Sprintf(format, args...)
		if !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		errBuf.WriteString(s)
	}
	for _, flag := range flags {
		switch flag {
		case "dynlink":
			ctxt.Flag_dynlink = true
		default:
			t.Errorf("unknown flag %s", flag)
		}
	}
	pList.Firstpc, ok = parser.Parse()
	obj.Flushplist(ctxt, pList, nil)
	if ok && !failed {
		t.Errorf("asm: %s had no errors", file)
	}

	errors := map[string]string{}
	for _, line := range strings.Split(errBuf.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "\t") {
			continue
		}
		m := fileLineRE.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("unexpected error: %v", line)
			continue
		}
		fileline := m[1]
		if errors[fileline] != "" && errors[fileline] != line {
			t.Errorf("multiple errors on %s:\n\t%s\n\t%s", fileline, errors[fileline], line)
			continue
		}
		errors[fileline] = line
	}

	// Reconstruct expected errors by independently "parsing" the input.
	data, err := os.ReadFile(input)
	if err != nil {
		t.Error(err)
		return
	}
	lineno := 0
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		lineno++

		fileline := fmt.Sprintf("%s:%d", input, lineno)
		if m := errRE.FindStringSubmatch(line); m != nil {
			all := m[1]
			mm := errQuotesRE.FindAllStringSubmatch(all, -1)
			if len(mm) != 1 {
				t.Errorf("%s: invalid errorcheck line:\n%s", fileline, line)
			} else if err := errors[fileline]; err == "" {
				t.Errorf("%s: missing error, want %s", fileline, all)
			} else if !strings.Contains(err, mm[0][1]) {
				t.Errorf("%s: wrong error for %s:\n%s", fileline, all, err)
			}
		} else {
			if errors[fileline] != "" {
				t.Errorf("unexpected error on %s: %v", fileline, errors[fileline])
			}
		}
		delete(errors, fileline)
	}
	var extra []string
	for key := range errors {
		extra = append(extra, key)
	}
	sort.Strings(extra)
	for _, fileline := range extra {
		t.Errorf("unexpected error on %s: %v", fileline, errors[fileline])
	}
}

func Test386EndToEnd(t *testing.T) {
	testEndToEnd(t, "386", "386")
}

func TestARMEndToEnd(t *testing.T) {
	defer func(old int) { buildcfg.GOARM.Version = old }(buildcfg.GOARM.Version)
	for _, goarm := range []int{5, 6, 7} {
		t.Logf("GOARM=%d", goarm)
		buildcfg.GOARM.Version = goarm
		testEndToEnd(t, "arm", "arm")
		if goarm == 6 {
			testEndToEnd(t, "arm", "armv6")
		}
	}
}

func TestGoBuildErrors(t *testing.T) {
	testErrors(t, "amd64", "buildtagerror")
}

func TestGenericErrors(t *testing.T) {
	testErrors(t, "amd64", "duperror")
}

func TestARMErrors(t *testing.T) {
	testErrors(t, "arm", "armerror")
}

func TestARM64EndToEnd(t *testing.T) {
	testEndToEnd(t, "arm64", "arm64")
}

func TestARM64Encoder(t *testing.T) {
	testEndToEnd(t, "arm64", "arm64enc")
}

func TestARM64Errors(t *testing.T) {
	testErrors(t, "arm64", "arm64error")
}

func TestAMD64EndToEnd(t *testing.T) {
	testEndToEnd(t, "amd64", "amd64")
}

func Test386Encoder(t *testing.T) {
	testEndToEnd(t, "386", "386enc")
}

func TestAMD64Encoder(t *testing.T) {
	filenames := [...]string{
		"amd64enc",
		"amd64enc_extra",
		"avx512enc/aes_avx512f",
		"avx512enc/gfni_avx512f",
		"avx512enc/vpclmulqdq_avx512f",
		"avx512enc/avx512bw",
		"avx512enc/avx512cd",
		"avx512enc/avx512dq",
		"avx512enc/avx512er",
		"avx512enc/avx512f",
		"avx512enc/avx512pf",
		"avx512enc/avx512_4fmaps",
		"avx512enc/avx512_4vnniw",
		"avx512enc/avx512_bitalg",
		"avx512enc/avx512_ifma",
		"avx512enc/avx512_vbmi",
		"avx512enc/avx512_vbmi2",
		"avx512enc/avx512_vnni",
		"avx512enc/avx512_vpopcntdq",
	}
	for _, name := range filenames {
		testEndToEnd(t, "amd64", name)
	}
}

func TestAMD64Errors(t *testing.T) {
	testErrors(t, "amd64", "amd64error")
}

func TestAMD64DynLinkErrors(t *testing.T) {
	testErrors(t, "amd64", "amd64dynlinkerror", "dynlink")
}

func TestMIPSEndToEnd(t *testing.T) {
	testEndToEnd(t, "mips", "mips")
	testEndToEnd(t, "mips64", "mips64")
}

func TestLOONG64Encoder(t *testing.T) {
	testEndToEnd(t, "loong64", "loong64enc1")
	testEndToEnd(t, "loong64", "loong64enc2")
	testEndToEnd(t, "loong64", "loong64enc3")
	testEndToEnd(t, "loong64", "loong64")
}

func TestPPC64EndToEnd(t *testing.T) {
	defer func(old int) { buildcfg.GOPPC64 = old }(buildcfg.GOPPC64)
	for _, goppc64 := range []int{8, 9, 10} {
		t.Logf("GOPPC64=power%d", goppc64)
		buildcfg.GOPPC64 = goppc64
		// Some pseudo-ops may assemble differently depending on GOPPC64
		testEndToEnd(t, "ppc64", "ppc64")
		testEndToEnd(t, "ppc64", "ppc64_p10")
	}
}

func TestRISCVEndToEnd(t *testing.T) {
	testEndToEnd(t, "riscv64", "riscv64")
}

func TestRISCVErrors(t *testing.T) {
	testErrors(t, "riscv64", "riscv64error")
}

func TestS390XEndToEnd(t *testing.T) {
	testEndToEnd(t, "s390x", "s390x")
}
```