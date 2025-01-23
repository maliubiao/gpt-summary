Response:
Let's break down the thought process for analyzing the `gofmt.go` code snippet.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, to infer its purpose, give code examples, explain command-line arguments, and point out potential user errors.

2. **Identify the Core Package:** The first step is to recognize the package declaration: `package main`. This immediately tells us it's an executable program. The import path `go/src/cmd/gofmt/gofmt.go` further confirms this and suggests it's the main file for the `gofmt` command.

3. **Analyze Imports:**  The imported packages offer significant clues about the program's functionality. Let's categorize them:
    * **File System & IO:** `os`, `io`, `io/fs`, `path/filepath` - Suggest file manipulation, reading, writing, and path handling.
    * **Go Language Parsing & Printing:** `go/ast`, `go/parser`, `go/printer`, `go/scanner`, `go/token` - Strongly indicate that the program works with Go source code by parsing it into an Abstract Syntax Tree (AST) and then formatting it.
    * **Concurrency & Synchronization:** `context`, `runtime`, `golang.org/x/sync/semaphore` - Point to the program's ability to process multiple files concurrently.
    * **String & Data Manipulation:** `bytes`, `strings`, `strconv` - Suggest operations on strings, likely for comparing and modifying code.
    * **Diffing:** `internal/diff` -  Indicates a feature to show differences between original and formatted code.
    * **Command Line Flags:** `flag` -  Confirms the program uses command-line arguments to control its behavior.
    * **Telemetry & Profiling (Less Core Functionality):** `cmd/internal/telemetry/counter`, `runtime/pprof` - Suggest features for performance monitoring and debugging.

4. **Examine Global Variables:** The `var` block declares several important variables:
    * **Mode Flags:** `list`, `write`, `rewriteRule`, `simplifyAST`, `doDiff`, `allErrors` - These are clearly command-line flags controlling different modes of operation. Their names are self-explanatory.
    * **Debugging Flag:** `cpuprofile` - Another command-line flag for profiling.
    * **Constants:** `tabWidth`, `printerMode`, `printerNormalizeNumbers` - These define the formatting style.
    * **Concurrency Control:** `fdSem` - A semaphore to limit concurrent file descriptor usage.
    * **Rewrite Function:** `rewrite` - A function variable likely used for the `-r` rewrite rule.
    * **Parser Mode:** `parserMode` - Controls the parsing behavior.

5. **Analyze Key Functions:**  Now, start looking at the core functions:
    * `usage()`: Prints the usage instructions, confirming it's a command-line tool.
    * `initParserMode()`: Configures the parser based on flags.
    * `isGoFile()`: Filters files to process only Go source files.
    * `sequencer`: A struct and its associated methods (`newSequencer`, `Add`, `AddReport`, `GetExitCode`) clearly implement a mechanism for concurrent processing with ordered output. This is crucial for handling multiple files.
    * `reporter`: A struct and its methods (`Warnf`, `Write`, `Report`, `ExitCode`) manage output and error reporting, ensuring sequential output from concurrent tasks.
    * `processFile()`: This is the heart of the formatting logic. It reads a file, parses it, applies rewrites and simplification (if requested), formats it using the `printer` package, and then handles the `-l`, `-w`, and `-d` flags.
    * `readFile()`: Handles reading file contents, with logic for handling potentially changing file sizes during reading.
    * `main()`: The entry point. It initializes the sequencer, calls `gofmtMain`, and exits.
    * `gofmtMain()`: Parses command-line flags, handles profiling, iterates through input paths (files or directories), and adds files to the sequencer for processing.
    * `fileWeight()`:  Determines the "weight" of a file for the sequencer, influencing concurrency.
    * `writeFile()`: Writes the formatted content back to the file, including backup logic.
    * `backupFile()`: Creates a backup of the original file before writing.

6. **Infer Go Language Functionality:** Based on the imports and function names, it's clear that `gofmt.go` is an implementation of a **Go code formatter**. It parses Go source code, applies formatting rules, and can either print the formatted output, write it back to the file, or show a diff.

7. **Develop Code Examples:** Now, create simple Go code examples that demonstrate the functionality. The examples should cover basic formatting and the rewrite rule.

8. **Explain Command-Line Arguments:**  Systematically go through each flag (`-l`, `-w`, `-r`, `-s`, `-d`, `-e`, `-cpuprofile`) and explain its purpose and how it modifies the program's behavior.

9. **Identify Potential User Errors:** Think about common mistakes users might make when using `gofmt`:
    * Using `-w` with standard input.
    * Expecting the rewrite rule to work on incomplete code snippets.
    * Forgetting that `gofmt` modifies files in place with `-w`.

10. **Structure the Answer:** Organize the findings into logical sections as requested: functionality, inferred Go feature, code examples, command-line arguments, and user errors. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe it's just a syntax checker. **Correction:** The presence of `go/printer` and the `-w` flag strongly suggest formatting.
* **Overlook details:** Initially, I might not have paid enough attention to the `sequencer`. **Refinement:** Realizing the concurrency control is a key aspect of how `gofmt` handles multiple files, I need to understand its purpose.
* **Ambiguous wording:**  Some initial descriptions of the flags might be unclear. **Refinement:** Rephrase to be more precise about what each flag does.
* **Missing examples:**  Initially, I might have only provided one code example. **Refinement:** Add more examples to demonstrate different features.

By following this structured approach, analyzing the code section by section, and focusing on the key components, you can effectively understand the functionality of the `gofmt.go` program.
这段代码是 Go 语言 `gofmt` 工具的一部分实现。`gofmt` 是 Go 语言官方提供的用于格式化 Go 源代码的工具，它遵循一套标准的 Go 代码风格规范，能够自动调整代码的缩进、空格、换行等，使代码风格保持一致。

下面列举一下 `gofmt.go` 这部分代码的主要功能：

1. **读取 Go 源代码:**  `processFile` 函数负责读取指定的 Go 源代码文件内容。它会尝试以最小的内存分配读取文件内容，并检测文件在读取过程中是否被修改。
2. **解析 Go 源代码:**  使用 `go/parser` 包将读取到的源代码解析成抽象语法树 (AST)。`initParserMode` 函数根据命令行参数 `-e` 来配置解析器的行为，例如是否报告所有错误。
3. **应用重写规则 (可选):** 如果使用了 `-r` 命令行参数指定了重写规则，则会调用 `rewrite` 函数（这部分代码未完全展示，但可以看到 `rewrite` 变量的声明和使用）来修改 AST。这个功能允许用户自定义代码转换规则。
4. **排序导入:**  `ast.SortImports` 函数用于对 Go 源代码中的 import 声明进行排序，使其符合规范。
5. **简化 AST (可选):** 如果使用了 `-s` 命令行参数，则会调用 `simplify` 函数（这部分代码未展示）来简化 AST。这通常涉及到一些代码的清理和优化。
6. **格式化 Go 源代码:** 使用 `go/printer` 包将修改后的 AST 重新格式化成符合 Go 语言规范的源代码。`printerMode` 和 `tabWidth` 常量定义了格式化的具体风格，例如使用空格缩进和 Tab 宽度。
7. **比较格式化前后的代码:**  比较原始代码和格式化后的代码，判断代码是否发生了变化。
8. **列出需要格式化的文件 (可选):** 如果使用了 `-l` 命令行参数，并且代码被格式化后与原始代码不同，则会将文件名输出到标准输出。
9. **将格式化后的代码写回文件 (可选):** 如果使用了 `-w` 命令行参数，并且代码被格式化后与原始代码不同，则会将格式化后的代码覆盖写入到原始文件中。在写入前会创建备份文件。
10. **显示代码差异 (可选):** 如果使用了 `-d` 命令行参数，并且代码被格式化后与原始代码不同，则会将格式化前后的差异以 diff 格式输出。
11. **并发处理文件:**  使用了 `golang.org/x/sync/semaphore` 包来实现并发处理多个文件，提高了处理效率。`sequencer` 结构体负责管理并发任务的执行顺序和输出。
12. **处理标准输入:**  如果没有指定任何文件路径，`gofmt` 会从标准输入读取代码进行格式化，并将结果输出到标准输出。但 `-w` 参数不能与标准输入一起使用。
13. **错误处理和报告:**  代码中包含了一些错误处理逻辑，例如读取文件失败、解析失败等。`reporter` 结构体用于统一报告错误和警告信息。
14. **CPU 性能分析 (可选):** 如果使用了 `-cpuprofile` 命令行参数，则会将 CPU 性能分析数据写入到指定的文件中。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言代码**格式化工具**的实现。它的核心功能是将不符合 Go 代码风格规范的代码自动调整为符合规范的代码。

**Go 代码举例说明:**

假设我们有一个名为 `example.go` 的文件，内容如下：

```go
package main

import "fmt"

func main() {
fmt.Println(    "Hello, World!")
}
```

**假设的输入与输出:**

**1. 使用 `gofmt example.go` (默认行为):**

* **输入:** 上述 `example.go` 文件的内容。
* **输出:** 格式化后的内容输出到标准输出：

```go
package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
```

**2. 使用 `gofmt -l example.go`:**

* **输入:** 上述 `example.go` 文件的内容。
* **输出:** 由于文件需要格式化，因此输出文件名：

```
example.go
```

**3. 使用 `gofmt -w example.go`:**

* **输入:** 上述 `example.go` 文件的内容。
* **输出:** (无输出到标准输出) `example.go` 文件内容被修改为：

```go
package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
```

* 同时会创建一个备份文件，例如 `example.go.12345` (数字随机)。

**4. 使用 `gofmt -d example.go`:**

* **输入:** 上述 `example.go` 文件的内容。
* **输出:**  显示格式化前后的差异：

```diff
--- example.go.orig
+++ example.go
@@ -1,7 +1,6 @@
 package main

 import "fmt"

 func main() {
-fmt.Println(    "Hello, World!")
+	fmt.Println("Hello, World!")
 }
```

**命令行参数的具体处理:**

* **`-l` (list):**  列出格式与 `gofmt` 输出不同的文件。不会修改文件内容。
* **`-w` (write):** 将格式化后的内容写回（覆盖）源文件。
* **`-r` (rewrite rule):**  应用指定的重写规则。例如，`gofmt -r 'a[b:len(a)] -> a[b:]' example.go` 会将切片操作 `a[b:len(a)]` 替换为 `a[b:]`。  `initRewrite()` 函数负责初始化重写逻辑（这部分代码未展示）。重写规则会先作用于 AST。
* **`-s` (simplify AST):** 尝试简化 AST，进行一些代码清理。具体的简化逻辑在 `simplify` 函数中实现（代码未展示）。
* **`-d` (display diffs):**  显示格式化前后的差异，而不是直接修改文件。
* **`-e` (all errors):**  在解析代码时报告所有错误，而不仅仅是前 10 个不同行的错误。这会影响 `initParserMode()` 中 `parserMode` 的设置。
* **`-cpuprofile` (cpuprofile):** 将 CPU 性能分析数据写入到指定的文件中，用于性能调试。

**使用者易犯错的点:**

1. **`-w` 与标准输入一起使用:**  `gofmt` 不允许将格式化后的标准输入内容写回文件，因为没有明确的文件名。代码中做了检查：

   ```go
   if len(args) == 0 {
       if *write {
           s.AddReport(fmt.Errorf("error: cannot use -w with standard input"))
           return
       }
       // ...
   }
   ```

   **错误示例:** `cat my_code.go | gofmt -w`  会导致错误。

2. **期望 `-r` 能处理不完整的代码片段:**  重写规则是基于完整的 AST 进行操作的。如果提供给 `gofmt` 的不是一个完整的 Go 文件，解析可能会失败，或者重写规则可能无法正确应用。代码中有相关提示：

   ```go
   if rewrite != nil {
       if sourceAdj == nil {
           file = rewrite(fileSet, file)
       } else {
           r.Warnf("warning: rewrite ignored for incomplete programs\n")
       }
   }
   ```

   `sourceAdj` 不为 `nil` 表示解析的是代码片段。

3. **忘记 `-w` 会直接修改文件:**  初学者可能会忘记 `-w` 参数会直接覆盖原始文件，导致未备份的代码被修改。`gofmt` 做了备份机制，但用户仍然需要注意。

4. **不理解并发处理可能带来的输出顺序问题 (虽然 `gofmt` 保证了顺序):** 虽然 `gofmt` 使用 `sequencer` 来保证输出顺序，但如果用户编写了依赖于执行顺序的自定义工具链，可能需要理解并发处理的机制。不过对于 `gofmt` 本身的用户来说，这通常不是一个问题。

总而言之，这段代码是 `gofmt` 工具的核心部分，负责读取、解析、格式化和输出 Go 源代码，并提供了一系列命令行选项来控制其行为。它对于维护 Go 项目的代码风格一致性至关重要。

### 提示词
```
这是路径为go/src/cmd/gofmt/gofmt.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"internal/diff"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"

	"cmd/internal/telemetry/counter"

	"golang.org/x/sync/semaphore"
)

var (
	// main operation modes
	list        = flag.Bool("l", false, "list files whose formatting differs from gofmt's")
	write       = flag.Bool("w", false, "write result to (source) file instead of stdout")
	rewriteRule = flag.String("r", "", "rewrite rule (e.g., 'a[b:len(a)] -> a[b:]')")
	simplifyAST = flag.Bool("s", false, "simplify code")
	doDiff      = flag.Bool("d", false, "display diffs instead of rewriting files")
	allErrors   = flag.Bool("e", false, "report all errors (not just the first 10 on different lines)")

	// debugging
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to this file")
)

// Keep these in sync with go/format/format.go.
const (
	tabWidth    = 8
	printerMode = printer.UseSpaces | printer.TabIndent | printerNormalizeNumbers

	// printerNormalizeNumbers means to canonicalize number literal prefixes
	// and exponents while printing. See https://golang.org/doc/go1.13#gofmt.
	//
	// This value is defined in go/printer specifically for go/format and cmd/gofmt.
	printerNormalizeNumbers = 1 << 30
)

// fdSem guards the number of concurrently-open file descriptors.
//
// For now, this is arbitrarily set to 200, based on the observation that many
// platforms default to a kernel limit of 256. Ideally, perhaps we should derive
// it from rlimit on platforms that support that system call.
//
// File descriptors opened from outside of this package are not tracked,
// so this limit may be approximate.
var fdSem = make(chan bool, 200)

var (
	rewrite    func(*token.FileSet, *ast.File) *ast.File
	parserMode parser.Mode
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: gofmt [flags] [path ...]\n")
	flag.PrintDefaults()
}

func initParserMode() {
	parserMode = parser.ParseComments
	if *allErrors {
		parserMode |= parser.AllErrors
	}
	// It's only -r that makes use of go/ast's object resolution,
	// so avoid the unnecessary work if the flag isn't used.
	if *rewriteRule == "" {
		parserMode |= parser.SkipObjectResolution
	}
}

func isGoFile(f fs.DirEntry) bool {
	// ignore non-Go files
	name := f.Name()
	return !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".go") && !f.IsDir()
}

// A sequencer performs concurrent tasks that may write output, but emits that
// output in a deterministic order.
type sequencer struct {
	maxWeight int64
	sem       *semaphore.Weighted   // weighted by input bytes (an approximate proxy for memory overhead)
	prev      <-chan *reporterState // 1-buffered
}

// newSequencer returns a sequencer that allows concurrent tasks up to maxWeight
// and writes tasks' output to out and err.
func newSequencer(maxWeight int64, out, err io.Writer) *sequencer {
	sem := semaphore.NewWeighted(maxWeight)
	prev := make(chan *reporterState, 1)
	prev <- &reporterState{out: out, err: err}
	return &sequencer{
		maxWeight: maxWeight,
		sem:       sem,
		prev:      prev,
	}
}

// exclusive is a weight that can be passed to a sequencer to cause
// a task to be executed without any other concurrent tasks.
const exclusive = -1

// Add blocks until the sequencer has enough weight to spare, then adds f as a
// task to be executed concurrently.
//
// If the weight is either negative or larger than the sequencer's maximum
// weight, Add blocks until all other tasks have completed, then the task
// executes exclusively (blocking all other calls to Add until it completes).
//
// f may run concurrently in a goroutine, but its output to the passed-in
// reporter will be sequential relative to the other tasks in the sequencer.
//
// If f invokes a method on the reporter, execution of that method may block
// until the previous task has finished. (To maximize concurrency, f should
// avoid invoking the reporter until it has finished any parallelizable work.)
//
// If f returns a non-nil error, that error will be reported after f's output
// (if any) and will cause a nonzero final exit code.
func (s *sequencer) Add(weight int64, f func(*reporter) error) {
	if weight < 0 || weight > s.maxWeight {
		weight = s.maxWeight
	}
	if err := s.sem.Acquire(context.TODO(), weight); err != nil {
		// Change the task from "execute f" to "report err".
		weight = 0
		f = func(*reporter) error { return err }
	}

	r := &reporter{prev: s.prev}
	next := make(chan *reporterState, 1)
	s.prev = next

	// Start f in parallel: it can run until it invokes a method on r, at which
	// point it will block until the previous task releases the output state.
	go func() {
		if err := f(r); err != nil {
			r.Report(err)
		}
		next <- r.getState() // Release the next task.
		s.sem.Release(weight)
	}()
}

// AddReport prints an error to s after the output of any previously-added
// tasks, causing the final exit code to be nonzero.
func (s *sequencer) AddReport(err error) {
	s.Add(0, func(*reporter) error { return err })
}

// GetExitCode waits for all previously-added tasks to complete, then returns an
// exit code for the sequence suitable for passing to os.Exit.
func (s *sequencer) GetExitCode() int {
	c := make(chan int, 1)
	s.Add(0, func(r *reporter) error {
		c <- r.ExitCode()
		return nil
	})
	return <-c
}

// A reporter reports output, warnings, and errors.
type reporter struct {
	prev  <-chan *reporterState
	state *reporterState
}

// reporterState carries the state of a reporter instance.
//
// Only one reporter at a time may have access to a reporterState.
type reporterState struct {
	out, err io.Writer
	exitCode int
}

// getState blocks until any prior reporters are finished with the reporter
// state, then returns the state for manipulation.
func (r *reporter) getState() *reporterState {
	if r.state == nil {
		r.state = <-r.prev
	}
	return r.state
}

// Warnf emits a warning message to the reporter's error stream,
// without changing its exit code.
func (r *reporter) Warnf(format string, args ...any) {
	fmt.Fprintf(r.getState().err, format, args...)
}

// Write emits a slice to the reporter's output stream.
//
// Any error is returned to the caller, and does not otherwise affect the
// reporter's exit code.
func (r *reporter) Write(p []byte) (int, error) {
	return r.getState().out.Write(p)
}

// Report emits a non-nil error to the reporter's error stream,
// changing its exit code to a nonzero value.
func (r *reporter) Report(err error) {
	if err == nil {
		panic("Report with nil error")
	}
	st := r.getState()
	scanner.PrintError(st.err, err)
	st.exitCode = 2
}

func (r *reporter) ExitCode() int {
	return r.getState().exitCode
}

// If info == nil, we are formatting stdin instead of a file.
// If in == nil, the source is the contents of the file with the given filename.
func processFile(filename string, info fs.FileInfo, in io.Reader, r *reporter) error {
	src, err := readFile(filename, info, in)
	if err != nil {
		return err
	}

	fileSet := token.NewFileSet()
	// If we are formatting stdin, we accept a program fragment in lieu of a
	// complete source file.
	fragmentOk := info == nil
	file, sourceAdj, indentAdj, err := parse(fileSet, filename, src, fragmentOk)
	if err != nil {
		return err
	}

	if rewrite != nil {
		if sourceAdj == nil {
			file = rewrite(fileSet, file)
		} else {
			r.Warnf("warning: rewrite ignored for incomplete programs\n")
		}
	}

	ast.SortImports(fileSet, file)

	if *simplifyAST {
		simplify(file)
	}

	res, err := format(fileSet, file, sourceAdj, indentAdj, src, printer.Config{Mode: printerMode, Tabwidth: tabWidth})
	if err != nil {
		return err
	}

	if !bytes.Equal(src, res) {
		// formatting has changed
		if *list {
			fmt.Fprintln(r, filename)
		}
		if *write {
			if info == nil {
				panic("-w should not have been allowed with stdin")
			}

			perm := info.Mode().Perm()
			if err := writeFile(filename, src, res, perm, info.Size()); err != nil {
				return err
			}
		}
		if *doDiff {
			newName := filepath.ToSlash(filename)
			oldName := newName + ".orig"
			r.Write(diff.Diff(oldName, src, newName, res))
		}
	}

	if !*list && !*write && !*doDiff {
		_, err = r.Write(res)
	}

	return err
}

// readFile reads the contents of filename, described by info.
// If in is non-nil, readFile reads directly from it.
// Otherwise, readFile opens and reads the file itself,
// with the number of concurrently-open files limited by fdSem.
func readFile(filename string, info fs.FileInfo, in io.Reader) ([]byte, error) {
	if in == nil {
		fdSem <- true
		var err error
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		in = f
		defer func() {
			f.Close()
			<-fdSem
		}()
	}

	// Compute the file's size and read its contents with minimal allocations.
	//
	// If we have the FileInfo from filepath.WalkDir, use it to make
	// a buffer of the right size and avoid ReadAll's reallocations.
	//
	// If the size is unknown (or bogus, or overflows an int), fall back to
	// a size-independent ReadAll.
	size := -1
	if info != nil && info.Mode().IsRegular() && int64(int(info.Size())) == info.Size() {
		size = int(info.Size())
	}
	if size+1 <= 0 {
		// The file is not known to be regular, so we don't have a reliable size for it.
		var err error
		src, err := io.ReadAll(in)
		if err != nil {
			return nil, err
		}
		return src, nil
	}

	// We try to read size+1 bytes so that we can detect modifications: if we
	// read more than size bytes, then the file was modified concurrently.
	// (If that happens, we could, say, append to src to finish the read, or
	// proceed with a truncated buffer — but the fact that it changed at all
	// indicates a possible race with someone editing the file, so we prefer to
	// stop to avoid corrupting it.)
	src := make([]byte, size+1)
	n, err := io.ReadFull(in, src)
	switch err {
	case nil, io.EOF, io.ErrUnexpectedEOF:
		// io.ReadFull returns io.EOF (for an empty file) or io.ErrUnexpectedEOF
		// (for a non-empty file) if the file was changed unexpectedly. Continue
		// with comparing file sizes in those cases.
	default:
		return nil, err
	}
	if n < size {
		return nil, fmt.Errorf("error: size of %s changed during reading (from %d to %d bytes)", filename, size, n)
	} else if n > size {
		return nil, fmt.Errorf("error: size of %s changed during reading (from %d to >=%d bytes)", filename, size, len(src))
	}
	return src[:n], nil
}

func main() {
	// Arbitrarily limit in-flight work to 2MiB times the number of threads.
	//
	// The actual overhead for the parse tree and output will depend on the
	// specifics of the file, but this at least keeps the footprint of the process
	// roughly proportional to GOMAXPROCS.
	maxWeight := (2 << 20) * int64(runtime.GOMAXPROCS(0))
	s := newSequencer(maxWeight, os.Stdout, os.Stderr)

	// call gofmtMain in a separate function
	// so that it can use defer and have them
	// run before the exit.
	gofmtMain(s)
	os.Exit(s.GetExitCode())
}

func gofmtMain(s *sequencer) {
	counter.Open()
	flag.Usage = usage
	flag.Parse()
	counter.Inc("gofmt/invocations")
	counter.CountFlags("gofmt/flag:", *flag.CommandLine)

	if *cpuprofile != "" {
		fdSem <- true
		f, err := os.Create(*cpuprofile)
		if err != nil {
			s.AddReport(fmt.Errorf("creating cpu profile: %s", err))
			return
		}
		defer func() {
			f.Close()
			<-fdSem
		}()
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	initParserMode()
	initRewrite()

	args := flag.Args()
	if len(args) == 0 {
		if *write {
			s.AddReport(fmt.Errorf("error: cannot use -w with standard input"))
			return
		}
		s.Add(0, func(r *reporter) error {
			return processFile("<standard input>", nil, os.Stdin, r)
		})
		return
	}

	for _, arg := range args {
		switch info, err := os.Stat(arg); {
		case err != nil:
			s.AddReport(err)
		case !info.IsDir():
			// Non-directory arguments are always formatted.
			arg := arg
			s.Add(fileWeight(arg, info), func(r *reporter) error {
				return processFile(arg, info, nil, r)
			})
		default:
			// Directories are walked, ignoring non-Go files.
			err := filepath.WalkDir(arg, func(path string, f fs.DirEntry, err error) error {
				if err != nil || !isGoFile(f) {
					return err
				}
				info, err := f.Info()
				if err != nil {
					s.AddReport(err)
					return nil
				}
				s.Add(fileWeight(path, info), func(r *reporter) error {
					return processFile(path, info, nil, r)
				})
				return nil
			})
			if err != nil {
				s.AddReport(err)
			}
		}
	}
}

func fileWeight(path string, info fs.FileInfo) int64 {
	if info == nil {
		return exclusive
	}
	if info.Mode().Type() == fs.ModeSymlink {
		var err error
		info, err = os.Stat(path)
		if err != nil {
			return exclusive
		}
	}
	if !info.Mode().IsRegular() {
		// For non-regular files, FileInfo.Size is system-dependent and thus not a
		// reliable indicator of weight.
		return exclusive
	}
	return info.Size()
}

// writeFile updates a file with the new formatted data.
func writeFile(filename string, orig, formatted []byte, perm fs.FileMode, size int64) error {
	// Make a temporary backup file before rewriting the original file.
	bakname, err := backupFile(filename, orig, perm)
	if err != nil {
		return err
	}

	fdSem <- true
	defer func() { <-fdSem }()

	fout, err := os.OpenFile(filename, os.O_WRONLY, perm)
	if err != nil {
		// We couldn't even open the file, so it should
		// not have changed.
		os.Remove(bakname)
		return err
	}
	defer fout.Close() // for error paths

	restoreFail := func(err error) {
		fmt.Fprintf(os.Stderr, "gofmt: %s: error restoring file to original: %v; backup in %s\n", filename, err, bakname)
	}

	n, err := fout.Write(formatted)
	if err == nil && int64(n) < size {
		err = fout.Truncate(int64(n))
	}

	if err != nil {
		// Rewriting the file failed.

		if n == 0 {
			// Original file unchanged.
			os.Remove(bakname)
			return err
		}

		// Try to restore the original contents.

		no, erro := fout.WriteAt(orig, 0)
		if erro != nil {
			// That failed too.
			restoreFail(erro)
			return err
		}

		if no < n {
			// Original file is shorter. Truncate.
			if erro = fout.Truncate(int64(no)); erro != nil {
				restoreFail(erro)
				return err
			}
		}

		if erro := fout.Close(); erro != nil {
			restoreFail(erro)
			return err
		}

		// Original contents restored.
		os.Remove(bakname)
		return err
	}

	if err := fout.Close(); err != nil {
		restoreFail(err)
		return err
	}

	// File updated.
	os.Remove(bakname)
	return nil
}

// backupFile writes data to a new file named filename<number> with permissions perm,
// with <number> randomly chosen such that the file name is unique. backupFile returns
// the chosen file name.
func backupFile(filename string, data []byte, perm fs.FileMode) (string, error) {
	fdSem <- true
	defer func() { <-fdSem }()

	nextRandom := func() string {
		return strconv.Itoa(rand.Int())
	}

	dir, base := filepath.Split(filename)
	var (
		bakname string
		f       *os.File
	)
	for {
		bakname = filepath.Join(dir, base+"."+nextRandom())
		var err error
		f, err = os.OpenFile(bakname, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return "", err
		}
	}

	// write data to backup file
	_, err := f.Write(data)
	if err1 := f.Close(); err == nil {
		err = err1
	}

	return bakname, err
}
```