Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The first step is to recognize the overarching purpose of the code. The comment `// This file contains routines related to the generation of annotated source listings.` immediately tells us it's about creating human-readable source code with performance data overlaid. The package name `report` and the function names like `printSource` and `MakeWebList` reinforce this idea.

2. **Identify Key Functions and Data Structures:** Next, I scanned for the main entry points and the core data structures involved.

    * **`printSource(w io.Writer, rpt *Report) error`**: This seems to be the primary function for generating a text-based annotated listing.
    * **`MakeWebList(rpt *Report, obj plugin.ObjTool, maxFiles int) (WebListData, error)`**:  This clearly aims to produce data for an HTML-based listing. The `WebListData` return type confirms this.
    * **`sourcePrinter` struct**: This struct appears to hold the state required for generating the web listing, suggesting a more complex process than `printSource`.
    * **`sourceReader` struct**: This likely handles reading and caching source files.
    * **`WebListData`, `WebListFile`, `WebListFunc`, `WebListLine`, `WebListInstruction`, `WebListCall`**: These structures define the format of the data generated for the web listing.

3. **Analyze `printSource` Functionality:**  I examined the `printSource` function in detail.

    * **Input:**  It takes an `io.Writer` (for output) and a `*Report`. The `Report` likely contains the profiling data.
    * **Steps:**
        * It filters functions based on a regular expression (`o.Symbol`).
        * It groups nodes (representing code locations) by function and then by source file.
        * It reads source code using `newSourceReader`.
        * It iterates through matching functions and their source files.
        * It calculates and prints flat and cumulative sample counts for functions and lines.
        * It formats the output to include the source code with annotations.
    * **Output:**  Annotated source code printed to the provided `io.Writer`.

4. **Analyze `MakeWebList` Functionality:**  I then focused on `MakeWebList`.

    * **Input:**  It takes a `*Report`, a `plugin.ObjTool` (for interacting with object files), and `maxFiles`.
    * **Steps:**
        * It initializes a `sourcePrinter`.
        * It filters based on the symbol regexp.
        * It calls the `generate` method of the `sourcePrinter` to create the `WebListData`.
    * **Output:** A `WebListData` struct containing the information needed to render an HTML annotated source listing.

5. **Deep Dive into `sourcePrinter` and its `generate` Method:**  The `sourcePrinter` struct and its `generate` method seemed crucial for the web listing.

    * **`sourcePrinter` Fields:** I noted the fields like `reader`, `synth`, `objectTool`, `objects`, `sym`, `files`, `insts`, etc. These fields indicated the steps involved: reading source, handling synthetic code, interacting with object files for disassembly, filtering by symbol, and storing collected information.
    * **`generate` Method:**  I observed the steps: finalizing file counts, sorting files, and calling `generateFile` for each file.

6. **Trace the Data Flow (Implicit):** Although not explicitly stated in the prompt, I implicitly tracked how data flows through the functions. The `Report` is the primary input, and it's processed to extract relevant information and annotate the source code. The `sourcePrinter` acts as a stateful object to coordinate this process for the web listing.

7. **Identify Go Language Features:** I looked for specific Go features demonstrated in the code:

    * **Packages and Imports:**  The `package report` and `import (...)` are standard Go structuring elements.
    * **Structs:**  `sourcePrinter`, `WebListData`, etc., are used to define data structures.
    * **Interfaces:** `io.Writer` and `plugin.ObjTool` are interfaces, allowing for flexible implementations.
    * **Methods:** Functions associated with structs (e.g., `printSource` acting on a `Report`, methods on `sourcePrinter`).
    * **Maps and Slices:**  Used extensively for storing and manipulating data (e.g., `functionNodes`, `fileNodes`, `files`, `lines`).
    * **Regular Expressions:** The `regexp` package is used for filtering symbols.
    * **String Manipulation:** The `strings` package is used for various operations like trimming, padding, and splitting.
    * **Error Handling:** The functions return `error` and use `fmt.Errorf`.
    * **Sorting:** The `sort` package is used to order functions and files.

8. **Infer Go Functionality (Hypothesize):** Based on the code, I could infer that this code implements a *source code annotation tool*, likely part of a profiling utility (pprof). It takes profiling data and source code, and then overlays the performance information onto the source.

9. **Construct Example (Reasoning):** To illustrate the functionality, I considered a simple scenario: a Go function with some performance samples. I then reasoned how the `printSource` function would process this, matching the function name against the provided regexp and printing the annotated source. I focused on showing how the sample counts would be displayed alongside the code.

10. **Command-Line Parameter Handling (Analysis):** I examined how command-line parameters are likely handled. The code uses `rpt.options.Symbol` and `rpt.options.SourcePath`. This suggests that the `Report` struct contains an `options` field, which probably gets populated by parsing command-line arguments. I speculated on the likely command-line flags based on these field names.

11. **Common Mistakes (Consideration):** I thought about potential pitfalls for users. The reliance on correct source paths and the potential for confusion with regular expressions seemed like likely issues. The need for debug symbols for accurate assembly annotation also came to mind.

12. **Structure the Answer:** Finally, I organized my findings into the requested sections: 功能, 实现的Go语言功能, 代码举例, 命令行参数, 易犯错的点, ensuring the language was Chinese as requested. I used the extracted information and my inferences to create clear and concise explanations.
这段Go语言代码是 `pprof` 工具的一部分，负责生成带有性能数据注释的源代码列表。更具体地说，它实现了将性能剖析数据（例如CPU使用率、内存分配等）映射到源代码行，从而帮助开发者理解程序性能瓶颈的功能。

**它的主要功能包括：**

1. **读取性能剖析数据 (`Report`):**  接收包含性能样本的 `Report` 对象作为输入。
2. **根据正则表达式筛选函数 (`rpt.options.symbol`):**  允许用户通过正则表达式指定他们感兴趣的函数，只显示包含匹配样本的函数的源代码。
3. **查找源代码文件:**  根据函数信息中的文件名，在指定的路径 (`rpt.options.SourcePath`) 下查找对应的源代码文件。
4. **读取源代码:**  读取找到的源代码文件的内容。
5. **将性能数据与源代码行关联:**  将性能样本（例如，flat samples 和 cumulative samples）关联到源代码的特定行。
6. **生成带注释的源代码列表:**  将关联的性能数据（例如，执行次数、占用时间等）打印在对应的源代码行旁边。
7. **生成 HTML 格式的源代码列表 (`MakeWebList`):** 除了文本格式，还能生成用于网页显示的 HTML 格式的源代码列表，包含更丰富的交互信息，例如内联调用栈。
8. **反汇编并关联到源代码 (`sourcePrinter`):**  对于 HTML 格式，还会尝试反汇编目标代码，并将反汇编指令与源代码行关联，提供更底层的性能分析信息。

**它实现的 Go 语言功能，并用代码举例说明：**

1. **结构体 (Struct):**  代码中定义了多个结构体，例如 `Report`, `sourcePrinter`, `sourceFile`, `WebListData` 等，用于组织和存储数据。

   ```go
   package main

   import "fmt"

   // 假设的 Report 结构体，实际的 pprof 中会更复杂
   type Report struct {
       total   int64
       options ReportOptions
       // ... 其他字段
   }

   type ReportOptions struct {
       Symbol     *regexp.Regexp
       SourcePath string
       TrimPath   string
       // ... 其他字段
   }

   func main() {
       rpt := Report{
           total: 1000,
           options: ReportOptions{
               Symbol: regexp.MustCompile("myFunction"),
               SourcePath: "/path/to/my/code",
               TrimPath: "",
           },
       }
       fmt.Println(rpt.total) // 输出: 1000
       fmt.Println(rpt.options.Symbol) // 输出: myfunction
   }
   ```

2. **方法 (Method):** 结构体可以定义方法，例如 `printSource` 可以被 `Report` 类型的变量调用。

   ```go
   package main

   import (
       "fmt"
       "io"
   )

   // 假设的 Report 结构体
   type Report struct {
       total int64
   }

   // printSource 方法
   func (r *Report) printSource(w io.Writer) {
       fmt.Fprintf(w, "Total: %d\n", r.total)
   }

   func main() {
       rpt := Report{total: 12345}
       rpt.printSource(os.Stdout) // 输出: Total: 12345
   }
   ```

3. **接口 (Interface):** 代码中使用了 `io.Writer` 和 `plugin.ObjTool` 接口，实现了依赖倒置，使得代码更灵活和可测试。

   ```go
   package main

   import (
       "bytes"
       "fmt"
       "io"
   )

   type MyWriter struct {
       buffer bytes.Buffer
   }

   func (mw *MyWriter) Write(p []byte) (n int, err error) {
       return mw.buffer.Write(p)
   }

   func main() {
       rpt := Report{total: 54321}
       myWriter := &MyWriter{}
       rpt.printSource(myWriter)
       fmt.Println(myWriter.buffer.String()) // 输出: Total: 54321
   }
   ```

4. **正则表达式 (Regular Expression):** `regexp` 包用于根据模式匹配函数名。

   ```go
   package main

   import (
       "fmt"
       "regexp"
   )

   func main() {
       pattern := regexp.MustCompile("myFunc.*")
       functionName := "myFunction123"
       if pattern.MatchString(functionName) {
           fmt.Println("函数名匹配正则表达式") // 输出: 函数名匹配正则表达式
       }
   }
   ```

5. **文件操作 (File Operation):** `os` 和 `bufio` 包用于打开、读取和扫描源代码文件。

   ```go
   package main

   import (
       "bufio"
       "fmt"
       "os"
   )

   func main() {
       file, err := os.Open("example.txt")
       if err != nil {
           fmt.Println("打开文件失败:", err)
           return
       }
       defer file.Close()

       scanner := bufio.NewScanner(file)
       for scanner.Scan() {
           fmt.Println(scanner.Text())
       }

       if err := scanner.Err(); err != nil {
           fmt.Println("读取文件出错:", err)
       }
   }
   ```

6. **字符串操作 (String Operation):** `strings` 包用于处理文件名、修剪路径、填充字符串等。

   ```go
   package main

   import (
       "fmt"
       "strings"
   )

   func main() {
       path := "/path/to/my/file.go"
       trimmedPath := strings.TrimPrefix(path, "/path/to/")
       fmt.Println(trimmedPath) // 输出: my/file.go

       paddedString := strings.Repeat(" ", 10) + "Hello"
       fmt.Println(paddedString) // 输出:           Hello
   }
   ```

**代码推理示例 (假设的输入与输出):**

假设我们有一个名为 `myfunction.go` 的文件，内容如下：

```go
package main

import "fmt"

func myFunction() { // 行号 5
	fmt.Println("Hello from myFunction") // 行号 6
}

func main() { // 行号 9
	myFunction() // 行号 10
}
```

并且我们有一个包含 `myFunction` 样本的 `Report` 对象 `rpt`。

**输入 (假设):**

* `rpt`: 一个 `Report` 对象，其中包含对 `myFunction` 的性能样本数据。
* `w`: `os.Stdout` (标准输出)。
* `rpt.options.Symbol`: 编译后的正则表达式，例如 `regexp.MustCompile("myFunction")`。
* `rpt.options.SourcePath`:  包含 `myfunction.go` 的目录，例如 `/tmp/myproject/src/mypackage`。

**输出 (推测 `printSource` 函数的输出):**

```
Total: <总样本数>
ROUTINE ======================== main.myFunction in myfunction.go
<flat样本数> <cum样本数> (flat, cum) <百分比> of Total
         0          <累积样本数>      6:	fmt.Println("Hello from myFunction")
```

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它假定 `Report` 对象 (`rpt`) 已经包含了从命令行参数解析出的配置信息，例如：

* **`--symbol <正则表达式>`:**  对应 `rpt.options.Symbol`，用于指定要显示的函数名。例如：`pprof --symbol myFunction myprofile`。
* **`--source_path <路径>` 或 `-source_path <路径>`:** 对应 `rpt.options.SourcePath`，用于指定源代码搜索路径。例如：`pprof --source_path /opt/myproject/src myprofile`。
* **`--trim_path <路径>`:** 对应 `rpt.options.TrimPath`，用于从源代码路径中移除指定的前缀，方便在不同环境之间匹配源代码。例如：`pprof --trim_path /home/user/gopath/src`。

`pprof` 工具通常会使用像 `flag` 或其他命令行参数解析库来处理这些参数，并将解析结果填充到 `Report` 对象的相应字段中。

**使用者易犯错的点:**

1. **错误的 `source_path`:**  如果指定的 `source_path` 不包含源代码文件，`pprof` 将无法找到源代码并进行注释。这会导致输出中缺少源代码信息。

   **例如:** 用户运行 `pprof --source_path /tmp myprofile`，但源代码在 `/home/user/myproject/src` 中，`pprof` 就找不到源代码。

2. **正则表达式不匹配:**  如果提供的正则表达式 (`--symbol`) 与任何函数名都不匹配，`pprof` 将报告找不到匹配项。

   **例如:** 用户运行 `pprof --symbol myFunc myprofile`，但实际函数名为 `myFunction`，则不会有任何输出。

3. **缺少调试信息:**  对于 HTML 格式的源代码列表和反汇编功能，如果程序编译时没有包含足够的调试信息，`pprof` 可能无法准确地将反汇编指令与源代码关联，或者无法获取内联调用的信息。

4. **路径问题 (相对路径 vs 绝对路径):**  性能剖析文件中记录的源代码路径可能是相对路径或绝对路径。用户需要确保 `--source_path` 能正确解析这些路径。`--trim_path` 可以帮助解决不同环境下的路径差异问题，但如果配置不当，也可能导致找不到文件。

总而言之，这段代码是 `pprof` 工具中用于增强性能分析可视化能力的关键部分，它将底层的性能数据与开发者熟悉的源代码联系起来，从而极大地提高了定位和解决性能问题的效率。

Prompt: 
```
这是路径为go/src/cmd/vendor/github.com/google/pprof/internal/report/source.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package report

// This file contains routines related to the generation of annotated
// source listings.

import (
	"bufio"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/pprof/internal/graph"
	"github.com/google/pprof/internal/measurement"
	"github.com/google/pprof/internal/plugin"
	"github.com/google/pprof/profile"
)

// printSource prints an annotated source listing, include all
// functions with samples that match the regexp rpt.options.symbol.
// The sources are sorted by function name and then by filename to
// eliminate potential nondeterminism.
func printSource(w io.Writer, rpt *Report) error {
	o := rpt.options
	g := rpt.newGraph(nil)

	// Identify all the functions that match the regexp provided.
	// Group nodes for each matching function.
	var functions graph.Nodes
	functionNodes := make(map[string]graph.Nodes)
	for _, n := range g.Nodes {
		if !o.Symbol.MatchString(n.Info.Name) {
			continue
		}
		if functionNodes[n.Info.Name] == nil {
			functions = append(functions, n)
		}
		functionNodes[n.Info.Name] = append(functionNodes[n.Info.Name], n)
	}
	functions.Sort(graph.NameOrder)

	if len(functionNodes) == 0 {
		return fmt.Errorf("no matches found for regexp: %s", o.Symbol)
	}

	sourcePath := o.SourcePath
	if sourcePath == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("could not stat current dir: %v", err)
		}
		sourcePath = wd
	}
	reader := newSourceReader(sourcePath, o.TrimPath)

	fmt.Fprintf(w, "Total: %s\n", rpt.formatValue(rpt.total))
	for _, fn := range functions {
		name := fn.Info.Name

		// Identify all the source files associated to this function.
		// Group nodes for each source file.
		var sourceFiles graph.Nodes
		fileNodes := make(map[string]graph.Nodes)
		for _, n := range functionNodes[name] {
			if n.Info.File == "" {
				continue
			}
			if fileNodes[n.Info.File] == nil {
				sourceFiles = append(sourceFiles, n)
			}
			fileNodes[n.Info.File] = append(fileNodes[n.Info.File], n)
		}

		if len(sourceFiles) == 0 {
			fmt.Fprintf(w, "No source information for %s\n", name)
			continue
		}

		sourceFiles.Sort(graph.FileOrder)

		// Print each file associated with this function.
		for _, fl := range sourceFiles {
			filename := fl.Info.File
			fns := fileNodes[filename]
			flatSum, cumSum := fns.Sum()

			fnodes, _, err := getSourceFromFile(filename, reader, fns, 0, 0)
			fmt.Fprintf(w, "ROUTINE ======================== %s in %s\n", name, filename)
			fmt.Fprintf(w, "%10s %10s (flat, cum) %s of Total\n",
				rpt.formatValue(flatSum), rpt.formatValue(cumSum),
				measurement.Percentage(cumSum, rpt.total))

			if err != nil {
				fmt.Fprintf(w, " Error: %v\n", err)
				continue
			}

			for _, fn := range fnodes {
				fmt.Fprintf(w, "%10s %10s %6d:%s\n", valueOrDot(fn.Flat, rpt), valueOrDot(fn.Cum, rpt), fn.Info.Lineno, fn.Info.Name)
			}
		}
	}
	return nil
}

// sourcePrinter holds state needed for generating source+asm HTML listing.
type sourcePrinter struct {
	reader     *sourceReader
	synth      *synthCode
	objectTool plugin.ObjTool
	objects    map[string]plugin.ObjFile  // Opened object files
	sym        *regexp.Regexp             // May be nil
	files      map[string]*sourceFile     // Set of files to print.
	insts      map[uint64]instructionInfo // Instructions of interest (keyed by address).

	// Set of function names that we are interested in (because they had
	// a sample and match sym).
	interest map[string]bool

	// Mapping from system function names to printable names.
	prettyNames map[string]string
}

// addrInfo holds information for an address we are interested in.
type addrInfo struct {
	loc *profile.Location // Always non-nil
	obj plugin.ObjFile    // May be nil
}

// instructionInfo holds collected information for an instruction.
type instructionInfo struct {
	objAddr   uint64 // Address in object file (with base subtracted out)
	length    int    // Instruction length in bytes
	disasm    string // Disassembly of instruction
	file      string // For top-level function in which instruction occurs
	line      int    // For top-level function in which instruction occurs
	flat, cum int64  // Samples to report (divisor already applied)
}

// sourceFile contains collected information for files we will print.
type sourceFile struct {
	fname    string
	cum      int64
	flat     int64
	lines    map[int][]sourceInst // Instructions to show per line
	funcName map[int]string       // Function name per line
}

// sourceInst holds information for an instruction to be displayed.
type sourceInst struct {
	addr  uint64
	stack []callID // Inlined call-stack
}

// sourceFunction contains information for a contiguous range of lines per function we
// will print.
type sourceFunction struct {
	name       string
	begin, end int // Line numbers (end is not included in the range)
	flat, cum  int64
}

// addressRange is a range of addresses plus the object file that contains it.
type addressRange struct {
	begin, end uint64
	obj        plugin.ObjFile
	mapping    *profile.Mapping
	score      int64 // Used to order ranges for processing
}

// WebListData holds the data needed to generate HTML source code listing.
type WebListData struct {
	Total string
	Files []WebListFile
}

// WebListFile holds the per-file information for HTML source code listing.
type WebListFile struct {
	Funcs []WebListFunc
}

// WebListFunc holds the per-function information for HTML source code listing.
type WebListFunc struct {
	Name       string
	File       string
	Flat       string
	Cumulative string
	Percent    string
	Lines      []WebListLine
}

// WebListLine holds the per-source-line information for HTML source code listing.
type WebListLine struct {
	SrcLine      string
	HTMLClass    string
	Line         int
	Flat         string
	Cumulative   string
	Instructions []WebListInstruction
}

// WebListInstruction holds the per-instruction information for HTML source code listing.
type WebListInstruction struct {
	NewBlock     bool // Insert marker that indicates separation from previous block
	Flat         string
	Cumulative   string
	Synthetic    bool
	Address      uint64
	Disasm       string
	FileLine     string
	InlinedCalls []WebListCall
}

// WebListCall holds the per-inlined-call information for HTML source code listing.
type WebListCall struct {
	SrcLine  string
	FileBase string
	Line     int
}

// MakeWebList returns an annotated source listing of rpt.
// rpt.prof should contain inlined call info.
func MakeWebList(rpt *Report, obj plugin.ObjTool, maxFiles int) (WebListData, error) {
	sourcePath := rpt.options.SourcePath
	if sourcePath == "" {
		wd, err := os.Getwd()
		if err != nil {
			return WebListData{}, fmt.Errorf("could not stat current dir: %v", err)
		}
		sourcePath = wd
	}
	sp := newSourcePrinter(rpt, obj, sourcePath)
	if len(sp.interest) == 0 {
		return WebListData{}, fmt.Errorf("no matches found for regexp: %s", rpt.options.Symbol)
	}
	defer sp.close()
	return sp.generate(maxFiles, rpt), nil
}

func newSourcePrinter(rpt *Report, obj plugin.ObjTool, sourcePath string) *sourcePrinter {
	sp := &sourcePrinter{
		reader:      newSourceReader(sourcePath, rpt.options.TrimPath),
		synth:       newSynthCode(rpt.prof.Mapping),
		objectTool:  obj,
		objects:     map[string]plugin.ObjFile{},
		sym:         rpt.options.Symbol,
		files:       map[string]*sourceFile{},
		insts:       map[uint64]instructionInfo{},
		prettyNames: map[string]string{},
		interest:    map[string]bool{},
	}

	// If the regexp source can be parsed as an address, also match
	// functions that land on that address.
	var address *uint64
	if sp.sym != nil {
		if hex, err := strconv.ParseUint(sp.sym.String(), 0, 64); err == nil {
			address = &hex
		}
	}

	addrs := map[uint64]addrInfo{}
	flat := map[uint64]int64{}
	cum := map[uint64]int64{}

	// Record an interest in the function corresponding to lines[index].
	markInterest := func(addr uint64, loc *profile.Location, index int) {
		fn := loc.Line[index]
		if fn.Function == nil {
			return
		}
		sp.interest[fn.Function.Name] = true
		sp.interest[fn.Function.SystemName] = true
		if _, ok := addrs[addr]; !ok {
			addrs[addr] = addrInfo{loc, sp.objectFile(loc.Mapping)}
		}
	}

	// See if sp.sym matches line.
	matches := func(line profile.Line) bool {
		if line.Function == nil {
			return false
		}
		return sp.sym.MatchString(line.Function.Name) ||
			sp.sym.MatchString(line.Function.SystemName) ||
			sp.sym.MatchString(line.Function.Filename)
	}

	// Extract sample counts and compute set of interesting functions.
	for _, sample := range rpt.prof.Sample {
		value := rpt.options.SampleValue(sample.Value)
		if rpt.options.SampleMeanDivisor != nil {
			div := rpt.options.SampleMeanDivisor(sample.Value)
			if div != 0 {
				value /= div
			}
		}

		// Find call-sites matching sym.
		for i := len(sample.Location) - 1; i >= 0; i-- {
			loc := sample.Location[i]
			for _, line := range loc.Line {
				if line.Function == nil {
					continue
				}
				sp.prettyNames[line.Function.SystemName] = line.Function.Name
			}

			addr := loc.Address
			if addr == 0 {
				// Some profiles are missing valid addresses.
				addr = sp.synth.address(loc)
			}

			cum[addr] += value
			if i == 0 {
				flat[addr] += value
			}

			if sp.sym == nil || (address != nil && addr == *address) {
				// Interested in top-level entry of stack.
				if len(loc.Line) > 0 {
					markInterest(addr, loc, len(loc.Line)-1)
				}
				continue
			}

			// Search in inlined stack for a match.
			matchFile := (loc.Mapping != nil && sp.sym.MatchString(loc.Mapping.File))
			for j, line := range loc.Line {
				if (j == 0 && matchFile) || matches(line) {
					markInterest(addr, loc, j)
				}
			}
		}
	}

	sp.expandAddresses(rpt, addrs, flat)
	sp.initSamples(flat, cum)
	return sp
}

func (sp *sourcePrinter) close() {
	for _, objFile := range sp.objects {
		if objFile != nil {
			objFile.Close()
		}
	}
}

func (sp *sourcePrinter) expandAddresses(rpt *Report, addrs map[uint64]addrInfo, flat map[uint64]int64) {
	// We found interesting addresses (ones with non-zero samples) above.
	// Get covering address ranges and disassemble the ranges.
	ranges, unprocessed := sp.splitIntoRanges(rpt.prof, addrs, flat)
	sp.handleUnprocessed(addrs, unprocessed)

	// Trim ranges if there are too many.
	const maxRanges = 25
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].score > ranges[j].score
	})
	if len(ranges) > maxRanges {
		ranges = ranges[:maxRanges]
	}

	for _, r := range ranges {
		objBegin, err := r.obj.ObjAddr(r.begin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to compute objdump address for range start %x: %v\n", r.begin, err)
			continue
		}
		objEnd, err := r.obj.ObjAddr(r.end)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to compute objdump address for range end %x: %v\n", r.end, err)
			continue
		}
		base := r.begin - objBegin
		insts, err := sp.objectTool.Disasm(r.mapping.File, objBegin, objEnd, rpt.options.IntelSyntax)
		if err != nil {
			// TODO(sanjay): Report that the covered addresses are missing.
			continue
		}

		var lastFrames []plugin.Frame
		var lastAddr, maxAddr uint64
		for i, inst := range insts {
			addr := inst.Addr + base

			// Guard against duplicate output from Disasm.
			if addr <= maxAddr {
				continue
			}
			maxAddr = addr

			length := 1
			if i+1 < len(insts) && insts[i+1].Addr > inst.Addr {
				// Extend to next instruction.
				length = int(insts[i+1].Addr - inst.Addr)
			}

			// Get inlined-call-stack for address.
			frames, err := r.obj.SourceLine(addr)
			if err != nil {
				// Construct a frame from disassembler output.
				frames = []plugin.Frame{{Func: inst.Function, File: inst.File, Line: inst.Line}}
			}

			x := instructionInfo{objAddr: inst.Addr, length: length, disasm: inst.Text}
			if len(frames) > 0 {
				// We could consider using the outer-most caller's source
				// location so we give the some hint as to where the
				// inlining happened that led to this instruction. So for
				// example, suppose we have the following (inlined) call
				// chains for this instruction:
				//   F1->G->H
				//   F2->G->H
				// We could tag the instructions from the first call with
				// F1 and instructions from the second call with F2. But
				// that leads to a somewhat confusing display. So for now,
				// we stick with just the inner-most location (i.e., H).
				// In the future we will consider changing the display to
				// make caller info more visible.
				index := 0 // Inner-most frame
				x.file = frames[index].File
				x.line = frames[index].Line
			}
			sp.insts[addr] = x

			// We sometimes get instructions with a zero reported line number.
			// Make such instructions have the same line info as the preceding
			// instruction, if an earlier instruction is found close enough.
			const neighborhood = 32
			if len(frames) > 0 && frames[0].Line != 0 {
				lastFrames = frames
				lastAddr = addr
			} else if (addr-lastAddr <= neighborhood) && lastFrames != nil {
				frames = lastFrames
			}

			sp.addStack(addr, frames)
		}
	}
}

func (sp *sourcePrinter) addStack(addr uint64, frames []plugin.Frame) {
	// See if the stack contains a function we are interested in.
	for i, f := range frames {
		if !sp.interest[f.Func] {
			continue
		}

		// Record sub-stack under frame's file/line.
		fname := canonicalizeFileName(f.File)
		file := sp.files[fname]
		if file == nil {
			file = &sourceFile{
				fname:    fname,
				lines:    map[int][]sourceInst{},
				funcName: map[int]string{},
			}
			sp.files[fname] = file
		}
		callees := frames[:i]
		stack := make([]callID, 0, len(callees))
		for j := len(callees) - 1; j >= 0; j-- { // Reverse so caller is first
			stack = append(stack, callID{
				file: callees[j].File,
				line: callees[j].Line,
			})
		}
		file.lines[f.Line] = append(file.lines[f.Line], sourceInst{addr, stack})

		// Remember the first function name encountered per source line
		// and assume that that line belongs to that function.
		if _, ok := file.funcName[f.Line]; !ok {
			file.funcName[f.Line] = f.Func
		}
	}
}

// synthAsm is the special disassembler value used for instructions without an object file.
const synthAsm = ""

// handleUnprocessed handles addresses that were skipped by splitIntoRanges because they
// did not belong to a known object file.
func (sp *sourcePrinter) handleUnprocessed(addrs map[uint64]addrInfo, unprocessed []uint64) {
	// makeFrames synthesizes a []plugin.Frame list for the specified address.
	// The result will typically have length 1, but may be longer if address corresponds
	// to inlined calls.
	makeFrames := func(addr uint64) []plugin.Frame {
		loc := addrs[addr].loc
		stack := make([]plugin.Frame, 0, len(loc.Line))
		for _, line := range loc.Line {
			fn := line.Function
			if fn == nil {
				continue
			}
			stack = append(stack, plugin.Frame{
				Func: fn.Name,
				File: fn.Filename,
				Line: int(line.Line),
			})
		}
		return stack
	}

	for _, addr := range unprocessed {
		frames := makeFrames(addr)
		x := instructionInfo{
			objAddr: addr,
			length:  1,
			disasm:  synthAsm,
		}
		if len(frames) > 0 {
			x.file = frames[0].File
			x.line = frames[0].Line
		}
		sp.insts[addr] = x

		sp.addStack(addr, frames)
	}
}

// splitIntoRanges converts the set of addresses we are interested in into a set of address
// ranges to disassemble. It also returns the set of addresses found that did not have an
// associated object file and were therefore not added to an address range.
func (sp *sourcePrinter) splitIntoRanges(prof *profile.Profile, addrMap map[uint64]addrInfo, flat map[uint64]int64) ([]addressRange, []uint64) {
	// Partition addresses into two sets: ones with a known object file, and ones without.
	var addrs, unprocessed []uint64
	for addr, info := range addrMap {
		if info.obj != nil {
			addrs = append(addrs, addr)
		} else {
			unprocessed = append(unprocessed, addr)
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })

	const expand = 500 // How much to expand range to pick up nearby addresses.
	var result []addressRange
	for i, n := 0, len(addrs); i < n; {
		begin, end := addrs[i], addrs[i]
		sum := flat[begin]
		i++

		info := addrMap[begin]
		m := info.loc.Mapping
		obj := info.obj // Non-nil because of the partitioning done above.

		// Find following addresses that are close enough to addrs[i].
		for i < n && addrs[i] <= end+2*expand && addrs[i] < m.Limit {
			// When we expand ranges by "expand" on either side, the ranges
			// for addrs[i] and addrs[i-1] will merge.
			end = addrs[i]
			sum += flat[end]
			i++
		}
		if m.Start-begin >= expand {
			begin -= expand
		} else {
			begin = m.Start
		}
		if m.Limit-end >= expand {
			end += expand
		} else {
			end = m.Limit
		}

		result = append(result, addressRange{begin, end, obj, m, sum})
	}
	return result, unprocessed
}

func (sp *sourcePrinter) initSamples(flat, cum map[uint64]int64) {
	for addr, inst := range sp.insts {
		// Move all samples that were assigned to the middle of an instruction to the
		// beginning of that instruction. This takes care of samples that were recorded
		// against pc+1.
		instEnd := addr + uint64(inst.length)
		for p := addr; p < instEnd; p++ {
			inst.flat += flat[p]
			inst.cum += cum[p]
		}
		sp.insts[addr] = inst
	}
}

func (sp *sourcePrinter) generate(maxFiles int, rpt *Report) WebListData {
	// Finalize per-file counts.
	for _, file := range sp.files {
		seen := map[uint64]bool{}
		for _, line := range file.lines {
			for _, x := range line {
				if seen[x.addr] {
					// Same address can be displayed multiple times in a file
					// (e.g., if we show multiple inlined functions).
					// Avoid double-counting samples in this case.
					continue
				}
				seen[x.addr] = true
				inst := sp.insts[x.addr]
				file.cum += inst.cum
				file.flat += inst.flat
			}
		}
	}

	// Get sorted list of files to print.
	var files []*sourceFile
	for _, f := range sp.files {
		files = append(files, f)
	}
	order := func(i, j int) bool { return files[i].flat > files[j].flat }
	if maxFiles < 0 {
		// Order by name for compatibility with old code.
		order = func(i, j int) bool { return files[i].fname < files[j].fname }
		maxFiles = len(files)
	}
	sort.Slice(files, order)
	result := WebListData{
		Total: rpt.formatValue(rpt.total),
	}
	for i, f := range files {
		if i < maxFiles {
			result.Files = append(result.Files, sp.generateFile(f, rpt))
		}
	}
	return result
}

func (sp *sourcePrinter) generateFile(f *sourceFile, rpt *Report) WebListFile {
	var result WebListFile
	for _, fn := range sp.functions(f) {
		if fn.cum == 0 {
			continue
		}

		listfn := WebListFunc{
			Name:       fn.name,
			File:       f.fname,
			Flat:       rpt.formatValue(fn.flat),
			Cumulative: rpt.formatValue(fn.cum),
			Percent:    measurement.Percentage(fn.cum, rpt.total),
		}
		var asm []assemblyInstruction
		for l := fn.begin; l < fn.end; l++ {
			lineContents, ok := sp.reader.line(f.fname, l)
			if !ok {
				if len(f.lines[l]) == 0 {
					// Outside of range of valid lines and nothing to print.
					continue
				}
				if l == 0 {
					// Line number 0 shows up if line number is not known.
					lineContents = "<instructions with unknown line numbers>"
				} else {
					// Past end of file, but have data to print.
					lineContents = "???"
				}
			}

			// Make list of assembly instructions.
			asm = asm[:0]
			var flatSum, cumSum int64
			var lastAddr uint64
			for _, inst := range f.lines[l] {
				addr := inst.addr
				x := sp.insts[addr]
				flatSum += x.flat
				cumSum += x.cum
				startsBlock := (addr != lastAddr+uint64(sp.insts[lastAddr].length))
				lastAddr = addr

				// divisors already applied, so leave flatDiv,cumDiv as 0
				asm = append(asm, assemblyInstruction{
					address:     x.objAddr,
					instruction: x.disasm,
					function:    fn.name,
					file:        x.file,
					line:        x.line,
					flat:        x.flat,
					cum:         x.cum,
					startsBlock: startsBlock,
					inlineCalls: inst.stack,
				})
			}

			listfn.Lines = append(listfn.Lines, makeWebListLine(l, flatSum, cumSum, lineContents, asm, sp.reader, rpt))
		}

		result.Funcs = append(result.Funcs, listfn)
	}
	return result
}

// functions splits apart the lines to show in a file into a list of per-function ranges.
func (sp *sourcePrinter) functions(f *sourceFile) []sourceFunction {
	var funcs []sourceFunction

	// Get interesting lines in sorted order.
	lines := make([]int, 0, len(f.lines))
	for l := range f.lines {
		lines = append(lines, l)
	}
	sort.Ints(lines)

	// Merge adjacent lines that are in same function and not too far apart.
	const mergeLimit = 20
	for _, l := range lines {
		name := f.funcName[l]
		if pretty, ok := sp.prettyNames[name]; ok {
			// Use demangled name if available.
			name = pretty
		}

		fn := sourceFunction{name: name, begin: l, end: l + 1}
		for _, x := range f.lines[l] {
			inst := sp.insts[x.addr]
			fn.flat += inst.flat
			fn.cum += inst.cum
		}

		// See if we should merge into preceding function.
		if len(funcs) > 0 {
			last := funcs[len(funcs)-1]
			if l-last.end < mergeLimit && last.name == name {
				last.end = l + 1
				last.flat += fn.flat
				last.cum += fn.cum
				funcs[len(funcs)-1] = last
				continue
			}
		}

		// Add new function.
		funcs = append(funcs, fn)
	}

	// Expand function boundaries to show neighborhood.
	const expand = 5
	for i, f := range funcs {
		if i == 0 {
			// Extend backwards, stopping at line number 1, but do not disturb 0
			// since that is a special line number that can show up when addr2line
			// cannot determine the real line number.
			if f.begin > expand {
				f.begin -= expand
			} else if f.begin > 1 {
				f.begin = 1
			}
		} else {
			// Find gap from predecessor and divide between predecessor and f.
			halfGap := (f.begin - funcs[i-1].end) / 2
			if halfGap > expand {
				halfGap = expand
			}
			funcs[i-1].end += halfGap
			f.begin -= halfGap
		}
		funcs[i] = f
	}

	// Also extend the ending point of the last function.
	if len(funcs) > 0 {
		funcs[len(funcs)-1].end += expand
	}

	return funcs
}

// objectFile return the object for the specified mapping, opening it if necessary.
// It returns nil on error.
func (sp *sourcePrinter) objectFile(m *profile.Mapping) plugin.ObjFile {
	if m == nil {
		return nil
	}
	if object, ok := sp.objects[m.File]; ok {
		return object // May be nil if we detected an error earlier.
	}
	object, err := sp.objectTool.Open(m.File, m.Start, m.Limit, m.Offset, m.KernelRelocationSymbol)
	if err != nil {
		object = nil
	}
	sp.objects[m.File] = object // Cache even on error.
	return object
}

// makeWebListLine returns the contents of a single line in a web listing. This includes
// the source line and the corresponding assembly.
func makeWebListLine(lineNo int, flat, cum int64, lineContents string,
	assembly []assemblyInstruction, reader *sourceReader, rpt *Report) WebListLine {
	line := WebListLine{
		SrcLine:    lineContents,
		Line:       lineNo,
		Flat:       valueOrDot(flat, rpt),
		Cumulative: valueOrDot(cum, rpt),
	}

	if len(assembly) == 0 {
		line.HTMLClass = "nop"
		return line
	}

	nestedInfo := false
	line.HTMLClass = "deadsrc"
	for _, an := range assembly {
		if len(an.inlineCalls) > 0 || an.instruction != synthAsm {
			nestedInfo = true
			line.HTMLClass = "livesrc"
		}
	}

	if nestedInfo {
		srcIndent := indentation(lineContents)
		line.Instructions = makeWebListInstructions(srcIndent, assembly, reader, rpt)
	}
	return line
}

func makeWebListInstructions(srcIndent int, assembly []assemblyInstruction, reader *sourceReader, rpt *Report) []WebListInstruction {
	var result []WebListInstruction
	var curCalls []callID
	for i, an := range assembly {
		var fileline string
		if an.file != "" {
			fileline = fmt.Sprintf("%s:%d", template.HTMLEscapeString(filepath.Base(an.file)), an.line)
		}
		text := strings.Repeat(" ", srcIndent+4+4*len(an.inlineCalls)) + an.instruction
		inst := WebListInstruction{
			NewBlock:   (an.startsBlock && i != 0),
			Flat:       valueOrDot(an.flat, rpt),
			Cumulative: valueOrDot(an.cum, rpt),
			Synthetic:  (an.instruction == synthAsm),
			Address:    an.address,
			Disasm:     rightPad(text, 80),
			FileLine:   fileline,
		}

		// Add inlined call context.
		for j, c := range an.inlineCalls {
			if j < len(curCalls) && curCalls[j] == c {
				// Skip if same as previous instruction.
				continue
			}
			curCalls = nil
			fline, ok := reader.line(c.file, c.line)
			if !ok {
				fline = ""
			}
			srcCode := strings.Repeat(" ", srcIndent+4+4*j) + strings.TrimSpace(fline)
			inst.InlinedCalls = append(inst.InlinedCalls, WebListCall{
				SrcLine:  rightPad(srcCode, 80),
				FileBase: filepath.Base(c.file),
				Line:     c.line,
			})
		}
		curCalls = an.inlineCalls

		result = append(result, inst)
	}
	return result
}

// getSourceFromFile collects the sources of a function from a source
// file and annotates it with the samples in fns. Returns the sources
// as nodes, using the info.name field to hold the source code.
func getSourceFromFile(file string, reader *sourceReader, fns graph.Nodes, start, end int) (graph.Nodes, string, error) {
	lineNodes := make(map[int]graph.Nodes)

	// Collect source coordinates from profile.
	const margin = 5 // Lines before first/after last sample.
	if start == 0 {
		if fns[0].Info.StartLine != 0 {
			start = fns[0].Info.StartLine
		} else {
			start = fns[0].Info.Lineno - margin
		}
	} else {
		start -= margin
	}
	if end == 0 {
		end = fns[0].Info.Lineno
	}
	end += margin
	for _, n := range fns {
		lineno := n.Info.Lineno
		nodeStart := n.Info.StartLine
		if nodeStart == 0 {
			nodeStart = lineno - margin
		}
		nodeEnd := lineno + margin
		if nodeStart < start {
			start = nodeStart
		} else if nodeEnd > end {
			end = nodeEnd
		}
		lineNodes[lineno] = append(lineNodes[lineno], n)
	}
	if start < 1 {
		start = 1
	}

	var src graph.Nodes
	for lineno := start; lineno <= end; lineno++ {
		line, ok := reader.line(file, lineno)
		if !ok {
			break
		}
		flat, cum := lineNodes[lineno].Sum()
		src = append(src, &graph.Node{
			Info: graph.NodeInfo{
				Name:   strings.TrimRight(line, "\n"),
				Lineno: lineno,
			},
			Flat: flat,
			Cum:  cum,
		})
	}
	if err := reader.fileError(file); err != nil {
		return nil, file, err
	}
	return src, file, nil
}

// sourceReader provides access to source code with caching of file contents.
type sourceReader struct {
	// searchPath is a filepath.ListSeparator-separated list of directories where
	// source files should be searched.
	searchPath string

	// trimPath is a filepath.ListSeparator-separated list of paths to trim.
	trimPath string

	// files maps from path name to a list of lines.
	// files[*][0] is unused since line numbering starts at 1.
	files map[string][]string

	// errors collects errors encountered per file. These errors are
	// consulted before returning out of these module.
	errors map[string]error
}

func newSourceReader(searchPath, trimPath string) *sourceReader {
	return &sourceReader{
		searchPath,
		trimPath,
		make(map[string][]string),
		make(map[string]error),
	}
}

func (reader *sourceReader) fileError(path string) error {
	return reader.errors[path]
}

// line returns the line numbered "lineno" in path, or _,false if lineno is out of range.
func (reader *sourceReader) line(path string, lineno int) (string, bool) {
	lines, ok := reader.files[path]
	if !ok {
		// Read and cache file contents.
		lines = []string{""} // Skip 0th line
		f, err := openSourceFile(path, reader.searchPath, reader.trimPath)
		if err != nil {
			reader.errors[path] = err
		} else {
			s := bufio.NewScanner(f)
			for s.Scan() {
				lines = append(lines, s.Text())
			}
			f.Close()
			if s.Err() != nil {
				reader.errors[path] = err
			}
		}
		reader.files[path] = lines
	}
	if lineno <= 0 || lineno >= len(lines) {
		return "", false
	}
	return lines[lineno], true
}

// openSourceFile opens a source file from a name encoded in a profile. File
// names in a profile after can be relative paths, so search them in each of
// the paths in searchPath and their parents. In case the profile contains
// absolute paths, additional paths may be configured to trim from the source
// paths in the profile. This effectively turns the path into a relative path
// searching it using searchPath as usual).
func openSourceFile(path, searchPath, trim string) (*os.File, error) {
	path = trimPath(path, trim, searchPath)
	// If file is still absolute, require file to exist.
	if filepath.IsAbs(path) {
		f, err := os.Open(path)
		return f, err
	}
	// Scan each component of the path.
	for _, dir := range filepath.SplitList(searchPath) {
		// Search up for every parent of each possible path.
		for {
			filename := filepath.Join(dir, path)
			if f, err := os.Open(filename); err == nil {
				return f, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	return nil, fmt.Errorf("could not find file %s on path %s", path, searchPath)
}

// trimPath cleans up a path by removing prefixes that are commonly
// found on profiles plus configured prefixes.
// TODO(aalexand): Consider optimizing out the redundant work done in this
// function if it proves to matter.
func trimPath(path, trimPath, searchPath string) string {
	// Keep path variable intact as it's used below to form the return value.
	sPath, searchPath := filepath.ToSlash(path), filepath.ToSlash(searchPath)
	if trimPath == "" {
		// If the trim path is not configured, try to guess it heuristically:
		// search for basename of each search path in the original path and, if
		// found, strip everything up to and including the basename. So, for
		// example, given original path "/some/remote/path/my-project/foo/bar.c"
		// and search path "/my/local/path/my-project" the heuristic will return
		// "/my/local/path/my-project/foo/bar.c".
		for _, dir := range filepath.SplitList(searchPath) {
			want := "/" + filepath.Base(dir) + "/"
			if found := strings.Index(sPath, want); found != -1 {
				return path[found+len(want):]
			}
		}
	}
	// Trim configured trim prefixes.
	trimPaths := append(filepath.SplitList(filepath.ToSlash(trimPath)), "/proc/self/cwd/./", "/proc/self/cwd/")
	for _, trimPath := range trimPaths {
		if !strings.HasSuffix(trimPath, "/") {
			trimPath += "/"
		}
		if strings.HasPrefix(sPath, trimPath) {
			return path[len(trimPath):]
		}
	}
	return path
}

func indentation(line string) int {
	column := 0
	for _, c := range line {
		if c == ' ' {
			column++
		} else if c == '\t' {
			column++
			for column%8 != 0 {
				column++
			}
		} else {
			break
		}
	}
	return column
}

// rightPad pads the input with spaces on the right-hand-side to make it have
// at least width n. It treats tabs as enough spaces that lead to the next
// 8-aligned tab-stop.
func rightPad(s string, n int) string {
	var str strings.Builder

	// Convert tabs to spaces as we go so padding works regardless of what prefix
	// is placed before the result.
	column := 0
	for _, c := range s {
		column++
		if c == '\t' {
			str.WriteRune(' ')
			for column%8 != 0 {
				column++
				str.WriteRune(' ')
			}
		} else {
			str.WriteRune(c)
		}
	}
	for column < n {
		column++
		str.WriteRune(' ')
	}
	return str.String()
}

func canonicalizeFileName(fname string) string {
	fname = strings.TrimPrefix(fname, "/proc/self/cwd/")
	fname = strings.TrimPrefix(fname, "./")
	return filepath.Clean(fname)
}

"""



```