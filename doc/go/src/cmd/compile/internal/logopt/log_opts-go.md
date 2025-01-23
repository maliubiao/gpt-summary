Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - The Core Goal:**

The first step is to understand the *purpose* of this code. The comments at the beginning are crucial: "This implements (non)optimization logging for -json option to the Go compiler." This immediately tells us it's about recording information about compiler optimizations (and cases where optimizations *don't* happen). The `-json` flag suggests it's outputting data in JSON format.

**2. Dissecting the `-json` Flag Logic:**

The comments detail the format of the `-json` flag: `0,<destination>`. The `LogJsonOption` function confirms this. It parses the input, verifies the version is 0, and then calls `checkLogPath`. This immediately brings up questions:

* What is `checkLogPath` doing?  The comment "superficial early checking" hints at validation and preparation of the output directory.
* What's the significance of the version number `0`?  The comments mention future versions.
* How does the `<destination>` work? The comments discuss absolute paths, `file://` URIs, and potential issues with relative paths.

**3. Following the Data Flow:**

Next, I look for how the logging actually happens. The `LoggedOpt` struct seems central. It holds information about the optimization event. The `LogOpt` and `LogOptRange` functions are clearly the entry points for recording these events. They create a `LoggedOpt` and append it to `loggedOpts`. The mutex `mu` suggests concurrent access.

**4. JSON Structure and Formatting:**

The comments and struct definitions for `VersionHeader` and `Diagnostic` are vital. They describe the JSON output format. I note the resemblance to LSP (Language Server Protocol) diagnostic messages, which provides context for how this data might be used. The fields like `Range`, `Code`, `Message`, and `RelatedInformation` are key to understanding the type of information being logged.

**5. Outputting the Logs - `FlushLoggedOpts`:**

The `FlushLoggedOpts` function is responsible for writing the accumulated `LoggedOpt` data to the JSON files. The steps here are important:

* **Sorting:** `sort.Stable(byPos{ctxt, loggedOpts})` -  The logs are sorted by position, which makes sense for associating log entries with specific code locations.
* **Directory and File Creation:**  A subdirectory per package and a JSON file per source file are created. The `url.PathEscape` is used for naming, handling potentially problematic characters in package and file names.
* **JSON Encoding:**  The `json.Encoder` is used to write the `VersionHeader` and individual `Diagnostic` records.
* **Inlining Information:** The handling of `RelatedInformation` and the `appendInlinedPos` function are interesting. They show how information about inlined functions is included in the logs.
* **Diagnostic Explanations:** The code also handles adding more detailed explanations (nested `LoggedOpt` structures) within the `RelatedInformation`.

**6. Error Handling and Edge Cases:**

Throughout the code, there are `log.Fatal` calls for invalid input or errors during file creation. The handling of empty package names and the special case for Windows paths are also noteworthy.

**7. Putting it all together (and thinking about the "why"):**

By connecting these pieces, I start to understand the overall workflow:

1. The compiler is invoked with the `-json` flag.
2. `LogJsonOption` parses the flag and sets up the output directory.
3. During compilation, various compiler passes call `LogOpt` or `LogOptRange` to record optimization events.
4. These events are stored in `loggedOpts`.
5. After compilation, `FlushLoggedOpts` is called.
6. `FlushLoggedOpts` sorts the logs, creates the necessary directories and files, and writes the JSON output in the defined format.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  Maybe the logging is very simple.
* **Correction:**  The complexity of handling inlining and nested explanations in `RelatedInformation` shows it's more sophisticated than a basic log.

* **Initial thought:**  The output format is just arbitrary JSON.
* **Correction:**  The explicit mention of LSP and the use of LSP-like structures indicate a deliberate choice to align with a standard format. This makes the logs more useful for tools that understand LSP.

* **Initial thought:** The directory structure is straightforward.
* **Correction:** The `url.PathEscape` usage and the special handling of Windows paths show attention to detail and the need to handle a variety of package and file names safely.

By going through this detailed analysis, I can confidently answer the prompt, provide examples, and highlight potential issues.
这段代码是 Go 编译器的一部分，专门用于**记录（非）优化信息**，并将这些信息以 **JSON 格式**输出，主要用于支持编译器的 `-json` 选项。  它采用了与 **Language Server Protocol (LSP)** 类似的 Diagnostic 结构来表示这些优化信息。

以下是它的主要功能：

1. **解析并验证 `-json` 命令行选项:**
   - 负责解析 `-json` 标志的值，该值应为 `版本号,目标目录` 的格式，例如 `-json=0,/tmp/logopt`。
   - 验证版本号是否为 0（当前支持的版本）。
   - 检查目标目录是否存在，如果不存在则创建。

2. **记录优化信息:**
   - 提供了 `LogOpt` 和 `LogOptRange` 函数，用于在编译过程中记录发生的（或未发生的）优化事件。
   - `LogOpt` 记录一个单点位置的事件。
   - `LogOptRange` 记录一个范围位置的事件。
   - 记录的信息包括事件发生的位置、编译器阶段、函数名、优化类型（`what`）以及可选的目标信息（`target`）。

3. **组织和存储日志信息:**
   - 使用 `LoggedOpt` 结构体来存储单个优化事件的信息。
   - 使用一个全局切片 `loggedOpts` 来累积所有记录的优化事件。
   - 使用互斥锁 `mu` 来保护 `loggedOpts` 的并发访问。

4. **生成 JSON 输出:**
   - `FlushLoggedOpts` 函数负责将累积的优化信息写入 JSON 文件。
   - 它会根据包路径在指定的目标目录下创建子目录。
   - 对于每个源文件，它会创建一个以文件名命名的 JSON 文件，并将与该文件相关的优化信息写入其中。
   - JSON 文件的内容包括：
     - 一个包含版本号、包名、操作系统、架构、Go 版本和文件名的头部信息 (`VersionHeader`)。
     - 一系列符合 LSP Diagnostic 规范的 JSON 记录，每行一个。
     - 每个 `Diagnostic` 记录描述了一个优化事件，包含范围 (`Range`)、严重程度 (`Severity`，总是 `SeverityInformation`)、代码 (`Code`，如 "nilcheck", "cannotInline")、来源 (`Source`，总是 "go compiler")、消息 (`Message`) 以及相关的内联信息 (`RelatedInformation`)。

5. **处理内联信息:**
   - 如果优化事件发生在内联函数中，`RelatedInformation` 字段会包含内联调用的位置信息，从外层到内层排列。

6. **处理逃逸分析解释:**
   - 对于逃逸分析的解释，会在 `RelatedInformation` 中记录逃逸路径上的各个位置，可能包含内联位置。

7. **文件和目录命名:**
   - 使用 `url.PathEscape` 对包名和文件名进行编码，以避免在文件系统路径中出现问题字符。
   - 对于空包名，内部会替换为 `string(0)`，编码为 `%00`。

8. **与 LSP 的兼容性:**
   - 代码中的 `Diagnostic`, `Range`, `Position`, `Location`, `DiagnosticRelatedInformation` 等结构体定义与 gopls (Go 的 Language Server) 中的定义保持一致，以便于工具进行解析和使用。

**可以推理出它是什么 Go 语言功能的实现：编译器优化日志记录。**

**Go 代码示例：**

假设在编译 `example.go` 文件时，编译器决定不内联某个函数，并且发现了一个可以进行 nil check 优化的位置。

```go
// example.go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	var p *int
	println(*p) // Potential nil dereference
	add(1, 2)
}
```

使用以下命令编译：

```bash
go tool compile -json=0,/tmp/logopt example.go
```

在 `/tmp/logopt/main/example.json` 文件中可能会生成如下 JSON 输出（简化）：

```json
{"version":0,"package":"main","goos":"linux","goarch":"amd64","gc_version":"go1.21","file":"example.go"}
{"range":{"start":{"line":6,"character":8},"end":{"line":6,"character":8}},"severity":3,"code":"nilcheck","source":"go compiler","message":""}
{"range":{"start":{"line":1,"character":5},"end":{"line":3,"character":1}},"severity":3,"code":"cannotInline","source":"go compiler","message":"function too complex"}
```

**假设的输入与输出：**

**输入 (Go 源代码片段):**  如上面的 `example.go`

**编译器命令行参数:** `go tool compile -json=0,/tmp/logopt example.go`

**输出 ( `/tmp/logopt/main/example.json` 文件内容):** 如上面的 JSON 示例。

**命令行参数的具体处理：**

- `-json=<version>,<destination>`:
  - `<version>`:  必须是数字 `0`，表示当前日志格式版本。
  - `<destination>`: 指定日志输出的目录。可以是绝对路径，也可以是 `file://` 开头的 URI。
    - 如果是绝对路径（以 `/` 或操作系统特定的路径分隔符开头），则直接使用。
    - 如果以 `file://` 开头，则会解析 URI，提取路径部分。对于 Windows 路径（例如 `/C:`），会进行特殊处理。
    - 如果既不是绝对路径也不是 `file://` URI，则会报错。
  - `LogJsonOption` 函数负责解析这个标志。
  - `parseLogFlag` 辅助解析逗号分隔的版本号和目录。
  - `checkLogPath` 负责验证目录路径，如果不存在则创建目录。

**使用者易犯错的点：**

1. **忘记指定版本号 0:**  如果使用 `-json=/tmp/logopt` 而不是 `-json=0,/tmp/logopt`，编译器会报错。
2. **重复使用 `-json` 标志:**  如果命令行中多次出现 `-json` 标志，编译器会报错 "Cannot repeat -json flag"。
3. **目标目录不存在且无法创建:** 如果指定的目标目录不存在，并且由于权限等问题无法创建，编译器会报错。
4. **不理解输出的 JSON 结构:**  输出的 JSON 是为了机器可读性设计的，直接阅读可能不太直观。需要理解 LSP Diagnostic 的结构才能有效利用这些信息。例如，需要知道 `Range` 的 `start` 和 `end` 是零基的行号和字符位置。
5. **依赖相对路径:** 虽然 `file://` URI 可以指定相对路径，但这是不推荐的做法。因为编译过程中的当前目录可能会变化，导致日志输出位置不确定。

**示例说明易犯错的点：**

假设用户错误地使用了 `-json` 标志，没有指定版本号：

```bash
go tool compile -json=/tmp/mylogs example.go
```

编译器会报错：

```
go tool compile: -json option should be '<version>,<destination>' where <version> is a number
```

或者，如果用户指定了一个无法创建的目录：

```bash
go tool compile -json=0,/root/forbidden_log_dir example.go
```

编译器可能会报错（取决于权限）：

```
go tool compile: optimizer logging destination '<version>,<directory>' but could not create <directory>: err=mkdir /root/forbidden_log_dir: permission denied
```

总而言之，这段代码是 Go 编译器中一个重要的组成部分，它提供了详细的优化日志信息，这对于编译器开发者、性能分析工具以及 IDE 来说都非常有价值。通过遵循 LSP 的规范，使得这些日志更容易与其他工具集成和分析。

### 提示词
```
这是路径为go/src/cmd/compile/internal/logopt/log_opts.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logopt

import (
	"cmd/internal/obj"
	"cmd/internal/src"
	"encoding/json"
	"fmt"
	"internal/buildcfg"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// This implements (non)optimization logging for -json option to the Go compiler
// The option is -json 0,<destination>.
//
// 0 is the version number; to avoid the need for synchronized updates, if
// new versions of the logging appear, the compiler will support both, for a while,
// and clients will specify what they need.
//
// <destination> is a directory.
// Directories are specified with a leading / or os.PathSeparator,
// or more explicitly with file://directory.  The second form is intended to
// deal with corner cases on Windows, and to allow specification of a relative
// directory path (which is normally a bad idea, because the local directory
// varies a lot in a build, especially with modules and/or vendoring, and may
// not be writeable).
//
// For each package pkg compiled, a url.PathEscape(pkg)-named subdirectory
// is created.  For each source file.go in that package that generates
// diagnostics (no diagnostics means no file),
// a url.PathEscape(file)+".json"-named file is created and contains the
// logged diagnostics.
//
// For example, "cmd%2Finternal%2Fdwarf/%3Cautogenerated%3E.json"
// for "cmd/internal/dwarf" and <autogenerated> (which is not really a file, but the compiler sees it)
//
// If the package string is empty, it is replaced internally with string(0) which encodes to %00.
//
// Each log file begins with a JSON record identifying version,
// platform, and other context, followed by optimization-relevant
// LSP Diagnostic records, one per line (LSP version 3.15, no difference from 3.14 on the subset used here
// see https://microsoft.github.io/language-server-protocol/specifications/specification-3-15/ )
//
// The fields of a Diagnostic are used in the following way:
// Range: the outermost source position, for now begin and end are equal.
// Severity: (always) SeverityInformation (3)
// Source: (always) "go compiler"
// Code: a string describing the missed optimization, e.g., "nilcheck", "cannotInline", "isInBounds", "escape"
// Message: depending on code, additional information, e.g., the reason a function cannot be inlined.
// RelatedInformation: if the missed optimization actually occurred at a function inlined at Range,
//    then the sequence of inlined locations appears here, from (second) outermost to innermost,
//    each with message="inlineLoc".
//
//    In the case of escape analysis explanations, after any outer inlining locations,
//    the lines of the explanation appear, each potentially followed with its own inlining
//    location if the escape flow occurred within an inlined function.
//
// For example <destination>/cmd%2Fcompile%2Finternal%2Fssa/prove.json
// might begin with the following line (wrapped for legibility):
//
// {"version":0,"package":"cmd/compile/internal/ssa","goos":"darwin","goarch":"amd64",
//  "gc_version":"devel +e1b9a57852 Fri Nov 1 15:07:00 2019 -0400",
//  "file":"/Users/drchase/work/go/src/cmd/compile/internal/ssa/prove.go"}
//
// and later contain (also wrapped for legibility):
//
// {"range":{"start":{"line":191,"character":24},"end":{"line":191,"character":24}},
//  "severity":3,"code":"nilcheck","source":"go compiler","message":"",
//  "relatedInformation":[
//    {"location":{"uri":"file:///Users/drchase/work/go/src/cmd/compile/internal/ssa/func.go",
//                 "range":{"start":{"line":153,"character":16},"end":{"line":153,"character":16}}},
//     "message":"inlineLoc"}]}
//
// That is, at prove.go (implicit from context, provided in both filename and header line),
// line 191, column 24, a nilcheck occurred in the generated code.
// The relatedInformation indicates that this code actually came from
// an inlined call to func.go, line 153, character 16.
//
// prove.go:191:
// 	ft.orderS = f.newPoset()
// func.go:152 and 153:
//  func (f *Func) newPoset() *poset {
//	    if len(f.Cache.scrPoset) > 0 {
//
// In the case that the package is empty, the string(0) package name is also used in the header record, for example
//
//  go tool compile -json=0,file://logopt x.go       # no -p option to set the package
//  head -1 logopt/%00/x.json
//  {"version":0,"package":"\u0000","goos":"darwin","goarch":"amd64","gc_version":"devel +86487adf6a Thu Nov 7 19:34:56 2019 -0500","file":"x.go"}

type VersionHeader struct {
	Version   int    `json:"version"`
	Package   string `json:"package"`
	Goos      string `json:"goos"`
	Goarch    string `json:"goarch"`
	GcVersion string `json:"gc_version"`
	File      string `json:"file,omitempty"` // LSP requires an enclosing resource, i.e., a file
}

// DocumentURI, Position, Range, Location, Diagnostic, DiagnosticRelatedInformation all reuse json definitions from gopls.
// See https://github.com/golang/tools/blob/22afafe3322a860fcd3d88448768f9db36f8bc5f/internal/lsp/protocol/tsprotocol.go

type DocumentURI string

type Position struct {
	Line      uint `json:"line"`      // gopls uses float64, but json output is the same for integers
	Character uint `json:"character"` // gopls uses float64, but json output is the same for integers
}

// A Range in a text document expressed as (zero-based) start and end positions.
// A range is comparable to a selection in an editor. Therefore the end position is exclusive.
// If you want to specify a range that contains a line including the line ending character(s)
// then use an end position denoting the start of the next line.
type Range struct {
	/*Start defined:
	 * The range's start position
	 */
	Start Position `json:"start"`

	/*End defined:
	 * The range's end position
	 */
	End Position `json:"end"` // exclusive
}

// A Location represents a location inside a resource, such as a line inside a text file.
type Location struct {
	// URI is
	URI DocumentURI `json:"uri"`

	// Range is
	Range Range `json:"range"`
}

/* DiagnosticRelatedInformation defined:
 * Represents a related message and source code location for a diagnostic. This should be
 * used to point to code locations that cause or related to a diagnostics, e.g when duplicating
 * a symbol in a scope.
 */
type DiagnosticRelatedInformation struct {

	/*Location defined:
	 * The location of this related diagnostic information.
	 */
	Location Location `json:"location"`

	/*Message defined:
	 * The message of this related diagnostic information.
	 */
	Message string `json:"message"`
}

// DiagnosticSeverity defines constants
type DiagnosticSeverity uint

const (
	/*SeverityInformation defined:
	 * Reports an information.
	 */
	SeverityInformation DiagnosticSeverity = 3
)

// DiagnosticTag defines constants
type DiagnosticTag uint

/*Diagnostic defined:
 * Represents a diagnostic, such as a compiler error or warning. Diagnostic objects
 * are only valid in the scope of a resource.
 */
type Diagnostic struct {

	/*Range defined:
	 * The range at which the message applies
	 */
	Range Range `json:"range"`

	/*Severity defined:
	 * The diagnostic's severity. Can be omitted. If omitted it is up to the
	 * client to interpret diagnostics as error, warning, info or hint.
	 */
	Severity DiagnosticSeverity `json:"severity,omitempty"` // always SeverityInformation for optimizer logging.

	/*Code defined:
	 * The diagnostic's code, which usually appear in the user interface.
	 */
	Code string `json:"code,omitempty"` // LSP uses 'number | string' = gopls interface{}, but only string here, e.g. "boundsCheck", "nilcheck", etc.

	/*Source defined:
	 * A human-readable string describing the source of this
	 * diagnostic, e.g. 'typescript' or 'super lint'. It usually
	 * appears in the user interface.
	 */
	Source string `json:"source,omitempty"` // "go compiler"

	/*Message defined:
	 * The diagnostic's message. It usually appears in the user interface
	 */
	Message string `json:"message"` // sometimes used, provides additional information.

	/*Tags defined:
	 * Additional metadata about the diagnostic.
	 */
	Tags []DiagnosticTag `json:"tags,omitempty"` // always empty for logging optimizations.

	/*RelatedInformation defined:
	 * An array of related diagnostic information, e.g. when symbol-names within
	 * a scope collide all definitions can be marked via this property.
	 */
	RelatedInformation []DiagnosticRelatedInformation `json:"relatedInformation,omitempty"`
}

// A LoggedOpt is what the compiler produces and accumulates,
// to be converted to JSON for human or IDE consumption.
type LoggedOpt struct {
	pos          src.XPos      // Source code position at which the event occurred. If it is inlined, outer and all inlined locations will appear in JSON.
	lastPos      src.XPos      // Usually the same as pos; current exception is for reporting entire range of transformed loops
	compilerPass string        // Compiler pass.  For human/adhoc consumption; does not appear in JSON (yet)
	functionName string        // Function name.  For human/adhoc consumption; does not appear in JSON (yet)
	what         string        // The (non) optimization; "nilcheck", "boundsCheck", "inline", "noInline"
	target       []interface{} // Optional target(s) or parameter(s) of "what" -- what was inlined, why it was not, size of copy, etc. 1st is most important/relevant.
}

type logFormat uint8

const (
	None  logFormat = iota
	Json0           // version 0 for LSP 3.14, 3.15; future versions of LSP may change the format and the compiler may need to support both as clients are updated.
)

var Format = None
var dest string

// LogJsonOption parses and validates the version,directory value attached to the -json compiler flag.
func LogJsonOption(flagValue string) {
	version, directory := parseLogFlag("json", flagValue)
	if version != 0 {
		log.Fatal("-json version must be 0")
	}
	dest = checkLogPath(directory)
	Format = Json0
}

// parseLogFlag checks the flag passed to -json
// for version,destination format and returns the two parts.
func parseLogFlag(flag, value string) (version int, directory string) {
	if Format != None {
		log.Fatal("Cannot repeat -json flag")
	}
	commaAt := strings.Index(value, ",")
	if commaAt <= 0 {
		log.Fatalf("-%s option should be '<version>,<destination>' where <version> is a number", flag)
	}
	v, err := strconv.Atoi(value[:commaAt])
	if err != nil {
		log.Fatalf("-%s option should be '<version>,<destination>' where <version> is a number: err=%v", flag, err)
	}
	version = v
	directory = value[commaAt+1:]
	return
}

// isWindowsDriveURIPath returns true if the file URI is of the format used by
// Windows URIs. The url.Parse package does not specially handle Windows paths
// (see golang/go#6027), so we check if the URI path has a drive prefix (e.g. "/C:").
// (copied from tools/internal/span/uri.go)
// this is less comprehensive that the processing in filepath.IsAbs on Windows.
func isWindowsDriveURIPath(uri string) bool {
	if len(uri) < 4 {
		return false
	}
	return uri[0] == '/' && unicode.IsLetter(rune(uri[1])) && uri[2] == ':'
}

func parseLogPath(destination string) (string, string) {
	if filepath.IsAbs(destination) {
		return filepath.Clean(destination), ""
	}
	if strings.HasPrefix(destination, "file://") { // IKWIAD, or Windows C:\foo\bar\baz
		uri, err := url.Parse(destination)
		if err != nil {
			return "", fmt.Sprintf("optimizer logging destination looked like file:// URI but failed to parse: err=%v", err)
		}
		destination = uri.Host + uri.Path
		if isWindowsDriveURIPath(destination) {
			// strip leading / from /C:
			// unlike tools/internal/span/uri.go, do not uppercase the drive letter -- let filepath.Clean do what it does.
			destination = destination[1:]
		}
		return filepath.Clean(destination), ""
	}
	return "", fmt.Sprintf("optimizer logging destination %s was neither %s-prefixed directory nor file://-prefixed file URI", destination, string(filepath.Separator))
}

// checkLogPath does superficial early checking of the string specifying
// the directory to which optimizer logging is directed, and if
// it passes the test, stores the string in LO_dir.
func checkLogPath(destination string) string {
	path, complaint := parseLogPath(destination)
	if complaint != "" {
		log.Fatal(complaint)
	}
	err := os.MkdirAll(path, 0755)
	if err != nil {
		log.Fatalf("optimizer logging destination '<version>,<directory>' but could not create <directory>: err=%v", err)
	}
	return path
}

var loggedOpts []*LoggedOpt
var mu = sync.Mutex{} // mu protects loggedOpts.

// NewLoggedOpt allocates a new LoggedOpt, to later be passed to either NewLoggedOpt or LogOpt as "args".
// Pos is the source position (including inlining), what is the message, pass is which pass created the message,
// funcName is the name of the function
// A typical use for this to accumulate an explanation for a missed optimization, for example, why did something escape?
func NewLoggedOpt(pos, lastPos src.XPos, what, pass, funcName string, args ...interface{}) *LoggedOpt {
	pass = strings.Replace(pass, " ", "_", -1)
	return &LoggedOpt{pos, lastPos, pass, funcName, what, args}
}

// LogOpt logs information about a (usually missed) optimization performed by the compiler.
// Pos is the source position (including inlining), what is the message, pass is which pass created the message,
// funcName is the name of the function.
func LogOpt(pos src.XPos, what, pass, funcName string, args ...interface{}) {
	if Format == None {
		return
	}
	lo := NewLoggedOpt(pos, pos, what, pass, funcName, args...)
	mu.Lock()
	defer mu.Unlock()
	// Because of concurrent calls from back end, no telling what the order will be, but is stable-sorted by outer Pos before use.
	loggedOpts = append(loggedOpts, lo)
}

// LogOptRange is the same as LogOpt, but includes the ability to express a range of positions,
// not just a point.
func LogOptRange(pos, lastPos src.XPos, what, pass, funcName string, args ...interface{}) {
	if Format == None {
		return
	}
	lo := NewLoggedOpt(pos, lastPos, what, pass, funcName, args...)
	mu.Lock()
	defer mu.Unlock()
	// Because of concurrent calls from back end, no telling what the order will be, but is stable-sorted by outer Pos before use.
	loggedOpts = append(loggedOpts, lo)
}

// Enabled returns whether optimization logging is enabled.
func Enabled() bool {
	switch Format {
	case None:
		return false
	case Json0:
		return true
	}
	panic("Unexpected optimizer-logging level")
}

// byPos sorts diagnostics by source position.
type byPos struct {
	ctxt *obj.Link
	a    []*LoggedOpt
}

func (x byPos) Len() int { return len(x.a) }
func (x byPos) Less(i, j int) bool {
	return x.ctxt.OutermostPos(x.a[i].pos).Before(x.ctxt.OutermostPos(x.a[j].pos))
}
func (x byPos) Swap(i, j int) { x.a[i], x.a[j] = x.a[j], x.a[i] }

func writerForLSP(subdirpath, file string) io.WriteCloser {
	basename := file
	lastslash := strings.LastIndexAny(basename, "\\/")
	if lastslash != -1 {
		basename = basename[lastslash+1:]
	}
	lastdot := strings.LastIndex(basename, ".go")
	if lastdot != -1 {
		basename = basename[:lastdot]
	}
	basename = url.PathEscape(basename)

	// Assume a directory, make a file
	p := filepath.Join(subdirpath, basename+".json")
	w, err := os.Create(p)
	if err != nil {
		log.Fatalf("Could not create file %s for logging optimizer actions, %v", p, err)
	}
	return w
}

func fixSlash(f string) string {
	if os.PathSeparator == '/' {
		return f
	}
	return strings.Replace(f, string(os.PathSeparator), "/", -1)
}

func uriIfy(f string) DocumentURI {
	url := url.URL{
		Scheme: "file",
		Path:   fixSlash(f),
	}
	return DocumentURI(url.String())
}

// Return filename, replacing a first occurrence of $GOROOT with the
// actual value of the GOROOT (because LSP does not speak "$GOROOT").
func uprootedPath(filename string) string {
	if filename == "" {
		return "__unnamed__"
	}
	if buildcfg.GOROOT == "" || !strings.HasPrefix(filename, "$GOROOT/") {
		return filename
	}
	return buildcfg.GOROOT + filename[len("$GOROOT"):]
}

// FlushLoggedOpts flushes all the accumulated optimization log entries.
func FlushLoggedOpts(ctxt *obj.Link, slashPkgPath string) {
	if Format == None {
		return
	}

	sort.Stable(byPos{ctxt, loggedOpts}) // Stable is necessary to preserve the per-function order, which is repeatable.
	switch Format {

	case Json0: // LSP 3.15
		var posTmp, lastTmp []src.Pos
		var encoder *json.Encoder
		var w io.WriteCloser

		if slashPkgPath == "" {
			slashPkgPath = "\000"
		}
		subdirpath := filepath.Join(dest, url.PathEscape(slashPkgPath))
		err := os.MkdirAll(subdirpath, 0755)
		if err != nil {
			log.Fatalf("Could not create directory %s for logging optimizer actions, %v", subdirpath, err)
		}
		diagnostic := Diagnostic{Source: "go compiler", Severity: SeverityInformation}

		// For LSP, make a subdirectory for the package, and for each file foo.go, create foo.json in that subdirectory.
		currentFile := ""
		for _, x := range loggedOpts {
			posTmp, p0 := parsePos(ctxt, x.pos, posTmp)
			lastTmp, l0 := parsePos(ctxt, x.lastPos, lastTmp) // These match posTmp/p0 except for most-inline, and that often also matches.
			p0f := uprootedPath(p0.Filename())

			if currentFile != p0f {
				if w != nil {
					w.Close()
				}
				currentFile = p0f
				w = writerForLSP(subdirpath, currentFile)
				encoder = json.NewEncoder(w)
				encoder.Encode(VersionHeader{Version: 0, Package: slashPkgPath, Goos: buildcfg.GOOS, Goarch: buildcfg.GOARCH, GcVersion: buildcfg.Version, File: currentFile})
			}

			// The first "target" is the most important one.
			var target string
			if len(x.target) > 0 {
				target = fmt.Sprint(x.target[0])
			}

			diagnostic.Code = x.what
			diagnostic.Message = target
			diagnostic.Range = newRange(p0, l0)
			diagnostic.RelatedInformation = diagnostic.RelatedInformation[:0]

			appendInlinedPos(posTmp, lastTmp, &diagnostic)

			// Diagnostic explanation is stored in RelatedInformation after inlining info
			if len(x.target) > 1 {
				switch y := x.target[1].(type) {
				case []*LoggedOpt:
					for _, z := range y {
						posTmp, p0 := parsePos(ctxt, z.pos, posTmp)
						lastTmp, l0 := parsePos(ctxt, z.lastPos, lastTmp)
						loc := newLocation(p0, l0)
						msg := z.what
						if len(z.target) > 0 {
							msg = msg + ": " + fmt.Sprint(z.target[0])
						}

						diagnostic.RelatedInformation = append(diagnostic.RelatedInformation, DiagnosticRelatedInformation{Location: loc, Message: msg})
						appendInlinedPos(posTmp, lastTmp, &diagnostic)
					}
				}
			}

			encoder.Encode(diagnostic)
		}
		if w != nil {
			w.Close()
		}
	}
}

// newRange returns a single-position Range for the compiler source location p.
func newRange(p, last src.Pos) Range {
	return Range{Start: Position{p.Line(), p.Col()},
		End: Position{last.Line(), last.Col()}}
}

// newLocation returns the Location for the compiler source location p.
func newLocation(p, last src.Pos) Location {
	loc := Location{URI: uriIfy(uprootedPath(p.Filename())), Range: newRange(p, last)}
	return loc
}

// appendInlinedPos extracts inlining information from posTmp and append it to diagnostic.
func appendInlinedPos(posTmp, lastTmp []src.Pos, diagnostic *Diagnostic) {
	for i := 1; i < len(posTmp); i++ {
		loc := newLocation(posTmp[i], lastTmp[i])
		diagnostic.RelatedInformation = append(diagnostic.RelatedInformation, DiagnosticRelatedInformation{Location: loc, Message: "inlineLoc"})
	}
}

// parsePos expands a src.XPos into a slice of src.Pos, with the outermost first.
// It returns the slice, and the outermost.
func parsePos(ctxt *obj.Link, pos src.XPos, posTmp []src.Pos) ([]src.Pos, src.Pos) {
	posTmp = posTmp[:0]
	ctxt.AllPos(pos, func(p src.Pos) {
		posTmp = append(posTmp, p)
	})
	return posTmp, posTmp[0]
}
```