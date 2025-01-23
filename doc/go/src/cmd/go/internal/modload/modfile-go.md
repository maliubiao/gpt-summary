Response: My thinking process to analyze the provided Go code and answer the prompt went something like this:

1. **Understand the Goal:** The request asks for the functionalities of `modfile.go`, to infer its purpose within the `go` command, provide Go code examples, explain command-line parameter handling, and identify potential pitfalls for users.

2. **Initial Scan for Key Terms and Concepts:** I quickly scanned the code for recurring keywords and recognizable package names. I noticed:
    * `modfile`: This strongly suggests interaction with `go.mod` files.
    * `module`:  Indicates working with Go modules.
    * `require`, `replace`, `exclude`, `retract`: These are all directives within `go.mod`.
    * `ReadModFile`, `indexModFile`, `goModSummary`, `rawGoModData`: These function names are quite descriptive.
    * `lockedfile`:  Suggests file locking for concurrent access.
    * `cfg`: Likely related to Go command configuration.
    * `gover`: Probably deals with Go version comparisons and constraints.
    * `cmd/go/internal/base`, `cmd/go/internal/fsys`, etc.:  Indicates this code is part of the `go` command's internal implementation.

3. **Focus on the Core Function: `ReadModFile`:** This function seems like a crucial entry point. Its actions reveal key responsibilities:
    * Reading `go.mod` (with potential overlay).
    * Locking the file to prevent race conditions.
    * Parsing the file using `golang.org/x/mod/modfile`.
    * Checking the Go version constraint.
    * Ensuring a `module` declaration exists.

4. **Infer High-Level Functionality:** Based on the keywords and `ReadModFile`, I could deduce that `modfile.go` is responsible for:
    * **Parsing and interpreting `go.mod` files.**
    * **Managing module dependencies (require, replace, exclude).**
    * **Handling Go version compatibility.**
    * **Supporting module replacements.**
    * **Dealing with module retractions.**

5. **Examine Other Key Functions:**  I looked at other important functions to refine my understanding:
    * `indexModFile`: Creates an in-memory representation of the `go.mod` content, optimizing access.
    * `goModSummary` and `rawGoModSummary`:  Provide summarized information about `go.mod` files, potentially with different levels of detail and handling of replacements.
    * `Replacement`: Determines if a module is being replaced and returns the replacement path.
    * `CheckAllowed`, `CheckExclusions`, `CheckRetractions`: Implement the logic for filtering module versions based on `go.mod` directives and retractions.

6. **Connect to Go Language Features:**  I linked the functionalities to concrete Go module features:
    * **`go mod init`**:  The "missing module declaration" error in `ReadModFile` hints at this command.
    * **`require` directive**:  Functions like `indexModFile` and `goModSummary` clearly process this.
    * **`replace` directive**:  The `Replacement` function and `toReplaceMap` are directly related.
    * **`exclude` directive**:  `CheckExclusions` handles this.
    * **`retract` directive**: `CheckRetractions` and the `retraction` struct are key.
    * **`go` directive**:  Version checking in `ReadModFile`.
    * **`go mod edit`**: The error message about a missing module declaration suggests using this.

7. **Construct Go Code Examples:**  Based on the identified features, I crafted simple Go code examples illustrating how these features are expressed in a `go.mod` file. I focused on `require`, `replace`, `exclude`, and `retract`.

8. **Analyze Command-Line Parameters (Indirectly):**  While the code itself doesn't directly parse command-line arguments, it's used *by* the `go` command. I considered which `go` commands would interact with this code (e.g., `go mod tidy`, `go get`, `go build`) and how they might influence the behavior (e.g., `go mod tidy` potentially fixing `// indirect` comments).

9. **Identify Potential User Errors:** I thought about common mistakes developers make when working with Go modules:
    * Conflicting replacements.
    * Forgetting to run `go mod tidy`.
    * Issues with case sensitivity on different file systems.
    * Misunderstanding relative paths in `replace` directives.

10. **Refine and Organize:**  I reviewed my notes and structured the answer logically, starting with a high-level summary, then diving into specific functions, providing examples, and discussing potential errors. I aimed for clarity and conciseness. I made sure to explicitly address each part of the prompt.

This iterative process of scanning, inferring, connecting, and exemplifying allowed me to develop a comprehensive understanding of the `modfile.go` code and provide a detailed and accurate response. The descriptive function and variable names within the Go code were extremely helpful in this process.
`go/src/cmd/go/internal/modload/modfile.go` 文件是 Go 语言 `go` 命令中负责处理 `go.mod` 文件的核心部分。它的主要功能是：

**核心功能：解析、读取和管理 `go.mod` 文件**

1. **读取和解析 `go.mod` 文件 (`ReadModFile`)**:
   - 从指定路径读取 `go.mod` 文件的内容。
   - **文件锁定**: 在读取时会锁定文件，以防止并发修改导致数据不一致。对于 overlay 文件系统中的 `go.mod` 不会进行锁定。
   - **应用 overlay**: 如果存在 overlay 文件系统，会读取 overlay 中的 `go.mod`。
   - **解析**: 使用 `golang.org/x/mod/modfile` 包解析 `go.mod` 文件的内容，将其转换为结构化的数据。
   - **应用修复器 (`fix modfile.VersionFixer`)**: 在解析过程中，可以应用版本修复逻辑（如果有提供）。
   - **Go 版本检查**: 检查 `go.mod` 中声明的 `go` 版本是否高于当前 Go 工具链的版本，如果是，则返回错误。
   - **模块声明检查**: 确保 `go.mod` 文件中存在 `module` 声明。

2. **创建 `go.mod` 文件的索引 (`modFileIndex`)**:
   - 创建一个 `modFileIndex` 结构体，用于存储 `go.mod` 文件的关键信息，例如：
     - 文件内容 (`data`)
     - 是否应用了版本修复 (`dataNeedsFix`)
     - 模块路径和版本 (`module`)
     - Go 版本 (`goVersion`)
     - 工具链版本 (`toolchain`)
     - `require` 依赖 (`require`)
     - `replace` 替换 (`replace`)
     - `exclude` 排除 (`exclude`)
   - 这种索引可以提高后续访问 `go.mod` 文件信息的效率。

3. **检查模块是否被允许使用 (`CheckAllowed`, `CheckExclusions`, `CheckRetractions`)**:
   - **`CheckAllowed`**: 检查给定的模块版本是否被主模块的 `go.mod` 文件排除 (`exclude`) 或被其作者撤回 (`retract`)。
   - **`CheckExclusions`**: 检查给定的模块版本是否被主模块的 `go.mod` 文件中的 `exclude` 指令排除。
   - **`CheckRetractions`**: 检查给定的模块版本是否被其作者在 `go.mod` 文件中使用 `retract` 指令撤回。

4. **处理 `replace` 指令 (`Replacement`, `replacementFrom`, `canonicalizeReplacePath`)**:
   - **`Replacement`**: 获取给定模块的替换 (`replace`) 信息。如果模块被替换，则返回替换后的模块路径和版本。
   - **`replacementFrom`**:  在多个 `go.mod` 文件（工作区模式下）中查找模块的替换信息，并处理冲突的替换。
   - **`canonicalizeReplacePath`**: 将 `replace` 指令中的相对路径规范化为相对于工作区目录或模块目录的路径。

5. **获取 `go.mod` 文件的摘要信息 (`goModSummary`, `rawGoModSummary`)**:
   - **`goModSummary`**: 获取模块 `go.mod` 文件的摘要信息，考虑到可能的替换和排除规则。适用于依赖模块的 `go.mod` 文件。
   - **`rawGoModSummary`**: 获取模块 `go.mod` 文件的原始摘要信息，忽略任何可能的替换和排除规则。不应用于主模块。

6. **获取原始 `go.mod` 文件数据 (`rawGoModData`)**:
   - 获取指定模块的 `go.mod` 文件的原始字节数据。
   - 对于本地路径的模块，会读取本地文件。
   - 对于远程模块，会从模块代理或版本控制系统下载 `go.mod` 文件。

7. **查询最新的可用版本 (`queryLatestVersionIgnoringRetractions`)**:
   - 查询指定模块的最新版本，但会忽略被撤回或排除的版本。

8. **判断 `go.mod` 文件是否被修改 (`modFileIsDirty`)**:
   - 比较当前解析的 `go.mod` 文件内容与之前索引的内容，判断文件是否发生了实质性的改变。

**推理其实现的 Go 语言功能：模块依赖管理**

基于上述功能，可以推断 `modfile.go` 主要负责实现 Go 语言的 **模块依赖管理** 功能。它处理了 `go.mod` 文件的读取、解析、验证和管理，是 `go` 命令在处理模块依赖关系时的核心组件。

**Go 代码示例**

假设我们有一个简单的 `go.mod` 文件：

```
module example.com/myapp

go 1.18

require (
	github.com/gin-gonic/gin v1.8.1
	golang.org/x/text v0.3.7
)

replace golang.org/x/text => golang.org/x/text v0.3.8

exclude golang.org/x/net v0.7.0
```

以下是一些使用 `modfile.go` 中功能的概念性 Go 代码示例（注意：这些代码是高层次的，直接使用 `cmd/go/internal/modload` 包可能需要更复杂的环境设置）：

```go
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"cmd/go/internal/modload"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

func main() {
	gomodPath := filepath.Join(".", "go.mod") // 假设 go.mod 在当前目录

	// 读取和解析 go.mod 文件
	data, mf, err := modload.ReadModFile(gomodPath, nil)
	if err != nil {
		fmt.Println("Error reading go.mod:", err)
		os.Exit(1)
	}
	fmt.Println("go.mod content:\n", string(data))
	fmt.Println("Module path:", mf.Module.Mod.Path)
	fmt.Println("Go version:", mf.Go.Version)

	// 遍历 require 依赖
	fmt.Println("\nRequire dependencies:")
	for _, req := range mf.Require {
		fmt.Printf("%s %s (indirect: %t)\n", req.Mod.Path, req.Mod.Version, req.Indirect)
	}

	// 获取 replace 信息
	replaceModule := module.Version{Path: "golang.org/x/text"}
	replacement := modload.Replacement(replaceModule)
	fmt.Println("\nReplacement for", replaceModule.Path, ":", replacement)

	// 检查模块是否被排除
	excludedModule := module.Version{Path: "golang.org/x/net", Version: "v0.7.0"}
	err = modload.CheckExclusions(context.Background(), excludedModule)
	fmt.Println("\nCheck exclusions for", excludedModule, ":", err)

	// 获取 go.mod 文件摘要
	mainModule := module.Version{Path: "example.com/myapp"}
	summary, err := modload.GoModSummary(mainModule)
	if err != nil {
		fmt.Println("Error getting go.mod summary:", err)
	} else {
		fmt.Println("\nGo.mod summary - Go version:", summary.goVersion)
		fmt.Println("Go.mod summary - Require length:", len(summary.require))
	}
}
```

**假设的输入与输出**

**输入 (`go.mod` 文件内容):**

```
module example.com/myapp

go 1.18

require (
	github.com/gin-gonic/gin v1.8.1
	golang.org/x/text v0.3.7
)

replace golang.org/x/text => golang.org/x/text v0.3.8

exclude golang.org/x/net v0.7.0
```

**输出 (概念性输出，实际输出可能包含更多细节):**

```
go.mod content:
 module example.com/myapp

go 1.18

require (
	github.com/gin-gonic/gin v1.8.1
	golang.org/x/text v0.3.7
)

replace golang.org/x/text => golang.org/x/text v0.3.8

exclude golang.org/x/net v0.7.0

Module path: example.com/myapp
Go version: 1.18

Require dependencies:
github.com/gin-gonic/gin v1.8.1 (indirect: false)
golang.org/x/text v0.3.7 (indirect: false)

Replacement for golang.org/x/text : {golang.org/x/text v0.3.8}

Check exclusions for {golang.org/x/net v0.7.0} : disallowed module version

Go.mod summary - Go version: 1.18
Go.mod summary - Require length: 2
```

**命令行参数的具体处理**

`modfile.go` 本身并不直接处理命令行参数。它的功能是被 `cmd/go` 包中的其他部分调用，而那些部分会解析和处理命令行参数。

例如，当执行 `go mod tidy` 命令时，`cmd/go` 的相关代码会调用 `modload.ReadModFile` 来读取 `go.mod` 文件，然后使用解析后的信息来清理和更新 `go.mod` 和 `go.sum` 文件。

类似的，`go get <module>@<version>` 命令会涉及到 `modfile.go` 中的功能，例如在解析现有的 `go.mod` 文件、添加新的依赖或者检查版本冲突时。

**使用者易犯错的点**

1. **手动编辑 `go.mod` 文件时语法错误**: 用户可能在手动编辑 `go.mod` 文件时引入语法错误，导致 `go` 命令解析失败。

   **示例**:  忘记闭合 `require` 块的括号：

   ```
   require (
       github.com/gin-gonic/gin v1.8.1
       golang.org/x/text v0.3.7
   
   ```

   **错误信息**: 类似 "errors parsing go.mod: unexpected newline in require block"

2. **`replace` 指令的路径问题**: 用户可能在 `replace` 指令中使用错误的本地路径或版本号，导致模块解析或构建失败。

   **示例**: `replace` 指向一个不存在的本地目录：

   ```
   replace example.com/mylib => ../my-local-lib
   ```

   如果 `../my-local-lib` 不存在，`go` 命令在尝试解析依赖时会报错。

3. **不理解 `exclude` 和 `retract` 的作用**: 用户可能不清楚 `exclude` 是在本地排除依赖，而 `retract` 是模块作者声明不再使用的版本。混淆使用可能导致不期望的依赖解析结果。

4. **在工作区模式下 `replace` 的相对路径理解错误**:  在 `go work` 工作区模式下，`replace` 指令的相对路径是相对于 `go.work` 文件所在的目录，而不是单个 `go.mod` 文件。这容易导致路径配置错误。

5. **忘记运行 `go mod tidy`**: 在手动修改 `go.mod` 文件后，或者在切换分支导致依赖关系变化后，忘记运行 `go mod tidy` 可能导致 `go.mod` 和 `go.sum` 文件不一致，从而引发构建错误。

总而言之，`go/src/cmd/go/internal/modload/modfile.go` 是 Go 模块功能的核心实现之一，负责处理 `go.mod` 文件的各种操作，确保模块依赖管理的正确性和一致性。

### 提示词
```
这是路径为go/src/cmd/go/internal/modload/modfile.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package modload

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"cmd/go/internal/base"
	"cmd/go/internal/cfg"
	"cmd/go/internal/fsys"
	"cmd/go/internal/gover"
	"cmd/go/internal/lockedfile"
	"cmd/go/internal/modfetch"
	"cmd/go/internal/trace"
	"cmd/internal/par"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// ReadModFile reads and parses the mod file at gomod. ReadModFile properly applies the
// overlay, locks the file while reading, and applies fix, if applicable.
func ReadModFile(gomod string, fix modfile.VersionFixer) (data []byte, f *modfile.File, err error) {
	if fsys.Replaced(gomod) {
		// Don't lock go.mod if it's part of the overlay.
		// On Plan 9, locking requires chmod, and we don't want to modify any file
		// in the overlay. See #44700.
		data, err = os.ReadFile(fsys.Actual(gomod))
	} else {
		data, err = lockedfile.Read(gomod)
	}
	if err != nil {
		return nil, nil, err
	}

	f, err = modfile.Parse(gomod, data, fix)
	if err != nil {
		// Errors returned by modfile.Parse begin with file:line.
		return nil, nil, fmt.Errorf("errors parsing %s:\n%w", base.ShortPath(gomod), shortPathErrorList(err))
	}
	if f.Go != nil && gover.Compare(f.Go.Version, gover.Local()) > 0 {
		toolchain := ""
		if f.Toolchain != nil {
			toolchain = f.Toolchain.Name
		}
		return nil, nil, &gover.TooNewError{What: base.ShortPath(gomod), GoVersion: f.Go.Version, Toolchain: toolchain}
	}
	if f.Module == nil {
		// No module declaration. Must add module path.
		return nil, nil, fmt.Errorf("error reading %s: missing module declaration. To specify the module path:\n\tgo mod edit -module=example.com/mod", base.ShortPath(gomod))
	}

	return data, f, err
}

func shortPathErrorList(err error) error {
	var el modfile.ErrorList
	if errors.As(err, &el) {
		for i := range el {
			el[i].Filename = base.ShortPath(el[i].Filename)
		}
	}
	return err
}

// A modFileIndex is an index of data corresponding to a modFile
// at a specific point in time.
type modFileIndex struct {
	data         []byte
	dataNeedsFix bool // true if fixVersion applied a change while parsing data
	module       module.Version
	goVersion    string // Go version (no "v" or "go" prefix)
	toolchain    string
	require      map[module.Version]requireMeta
	replace      map[module.Version]module.Version
	exclude      map[module.Version]bool
}

type requireMeta struct {
	indirect bool
}

// A modPruning indicates whether transitive dependencies of Go 1.17 dependencies
// are pruned out of the module subgraph rooted at a given module.
// (See https://golang.org/ref/mod#graph-pruning.)
type modPruning uint8

const (
	pruned    modPruning = iota // transitive dependencies of modules at go 1.17 and higher are pruned out
	unpruned                    // no transitive dependencies are pruned out
	workspace                   // pruned to the union of modules in the workspace
)

func (p modPruning) String() string {
	switch p {
	case pruned:
		return "pruned"
	case unpruned:
		return "unpruned"
	case workspace:
		return "workspace"
	default:
		return fmt.Sprintf("%T(%d)", p, p)
	}
}

func pruningForGoVersion(goVersion string) modPruning {
	if gover.Compare(goVersion, gover.ExplicitIndirectVersion) < 0 {
		// The go.mod file does not duplicate relevant information about transitive
		// dependencies, so they cannot be pruned out.
		return unpruned
	}
	return pruned
}

// CheckAllowed returns an error equivalent to ErrDisallowed if m is excluded by
// the main module's go.mod or retracted by its author. Most version queries use
// this to filter out versions that should not be used.
func CheckAllowed(ctx context.Context, m module.Version) error {
	if err := CheckExclusions(ctx, m); err != nil {
		return err
	}
	if err := CheckRetractions(ctx, m); err != nil {
		return err
	}
	return nil
}

// ErrDisallowed is returned by version predicates passed to Query and similar
// functions to indicate that a version should not be considered.
var ErrDisallowed = errors.New("disallowed module version")

// CheckExclusions returns an error equivalent to ErrDisallowed if module m is
// excluded by the main module's go.mod file.
func CheckExclusions(ctx context.Context, m module.Version) error {
	for _, mainModule := range MainModules.Versions() {
		if index := MainModules.Index(mainModule); index != nil && index.exclude[m] {
			return module.VersionError(m, errExcluded)
		}
	}
	return nil
}

var errExcluded = &excludedError{}

type excludedError struct{}

func (e *excludedError) Error() string     { return "excluded by go.mod" }
func (e *excludedError) Is(err error) bool { return err == ErrDisallowed }

// CheckRetractions returns an error if module m has been retracted by
// its author.
func CheckRetractions(ctx context.Context, m module.Version) (err error) {
	defer func() {
		if retractErr := (*ModuleRetractedError)(nil); err == nil || errors.As(err, &retractErr) {
			return
		}
		// Attribute the error to the version being checked, not the version from
		// which the retractions were to be loaded.
		if mErr := (*module.ModuleError)(nil); errors.As(err, &mErr) {
			err = mErr.Err
		}
		err = &retractionLoadingError{m: m, err: err}
	}()

	if m.Version == "" {
		// Main module, standard library, or file replacement module.
		// Cannot be retracted.
		return nil
	}
	if repl := Replacement(module.Version{Path: m.Path}); repl.Path != "" {
		// All versions of the module were replaced.
		// Don't load retractions, since we'd just load the replacement.
		return nil
	}

	// Find the latest available version of the module, and load its go.mod. If
	// the latest version is replaced, we'll load the replacement.
	//
	// If there's an error loading the go.mod, we'll return it here. These errors
	// should generally be ignored by callers since they happen frequently when
	// we're offline. These errors are not equivalent to ErrDisallowed, so they
	// may be distinguished from retraction errors.
	//
	// We load the raw file here: the go.mod file may have a different module
	// path that we expect if the module or its repository was renamed.
	// We still want to apply retractions to other aliases of the module.
	rm, err := queryLatestVersionIgnoringRetractions(ctx, m.Path)
	if err != nil {
		return err
	}
	summary, err := rawGoModSummary(rm)
	if err != nil && !errors.Is(err, gover.ErrTooNew) {
		return err
	}

	var rationale []string
	isRetracted := false
	for _, r := range summary.retract {
		if gover.ModCompare(m.Path, r.Low, m.Version) <= 0 && gover.ModCompare(m.Path, m.Version, r.High) <= 0 {
			isRetracted = true
			if r.Rationale != "" {
				rationale = append(rationale, r.Rationale)
			}
		}
	}
	if isRetracted {
		return module.VersionError(m, &ModuleRetractedError{Rationale: rationale})
	}
	return nil
}

type ModuleRetractedError struct {
	Rationale []string
}

func (e *ModuleRetractedError) Error() string {
	msg := "retracted by module author"
	if len(e.Rationale) > 0 {
		// This is meant to be a short error printed on a terminal, so just
		// print the first rationale.
		msg += ": " + ShortMessage(e.Rationale[0], "retracted by module author")
	}
	return msg
}

func (e *ModuleRetractedError) Is(err error) bool {
	return err == ErrDisallowed
}

type retractionLoadingError struct {
	m   module.Version
	err error
}

func (e *retractionLoadingError) Error() string {
	return fmt.Sprintf("loading module retractions for %v: %v", e.m, e.err)
}

func (e *retractionLoadingError) Unwrap() error {
	return e.err
}

// ShortMessage returns a string from go.mod (for example, a retraction
// rationale or deprecation message) that is safe to print in a terminal.
//
// If the given string is empty, ShortMessage returns the given default. If the
// given string is too long or contains non-printable characters, ShortMessage
// returns a hard-coded string.
func ShortMessage(message, emptyDefault string) string {
	const maxLen = 500
	if i := strings.Index(message, "\n"); i >= 0 {
		message = message[:i]
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return emptyDefault
	}
	if len(message) > maxLen {
		return "(message omitted: too long)"
	}
	for _, r := range message {
		if !unicode.IsGraphic(r) && !unicode.IsSpace(r) {
			return "(message omitted: contains non-printable characters)"
		}
	}
	// NOTE: the go.mod parser rejects invalid UTF-8, so we don't check that here.
	return message
}

// CheckDeprecation returns a deprecation message from the go.mod file of the
// latest version of the given module. Deprecation messages are comments
// before or on the same line as the module directives that start with
// "Deprecated:" and run until the end of the paragraph.
//
// CheckDeprecation returns an error if the message can't be loaded.
// CheckDeprecation returns "", nil if there is no deprecation message.
func CheckDeprecation(ctx context.Context, m module.Version) (deprecation string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("loading deprecation for %s: %w", m.Path, err)
		}
	}()

	if m.Version == "" {
		// Main module, standard library, or file replacement module.
		// Don't look up deprecation.
		return "", nil
	}
	if repl := Replacement(module.Version{Path: m.Path}); repl.Path != "" {
		// All versions of the module were replaced.
		// We'll look up deprecation separately for the replacement.
		return "", nil
	}

	latest, err := queryLatestVersionIgnoringRetractions(ctx, m.Path)
	if err != nil {
		return "", err
	}
	summary, err := rawGoModSummary(latest)
	if err != nil && !errors.Is(err, gover.ErrTooNew) {
		return "", err
	}
	return summary.deprecated, nil
}

func replacement(mod module.Version, replace map[module.Version]module.Version) (fromVersion string, to module.Version, ok bool) {
	if r, ok := replace[mod]; ok {
		return mod.Version, r, true
	}
	if r, ok := replace[module.Version{Path: mod.Path}]; ok {
		return "", r, true
	}
	return "", module.Version{}, false
}

// Replacement returns the replacement for mod, if any. If the path in the
// module.Version is relative it's relative to the single main module outside
// workspace mode, or the workspace's directory in workspace mode.
func Replacement(mod module.Version) module.Version {
	r, foundModRoot, _ := replacementFrom(mod)
	return canonicalizeReplacePath(r, foundModRoot)
}

// replacementFrom returns the replacement for mod, if any, the modroot of the replacement if it appeared in a go.mod,
// and the source of the replacement. The replacement is relative to the go.work or go.mod file it appears in.
func replacementFrom(mod module.Version) (r module.Version, modroot string, fromFile string) {
	foundFrom, found, foundModRoot := "", module.Version{}, ""
	if MainModules == nil {
		return module.Version{}, "", ""
	} else if MainModules.Contains(mod.Path) && mod.Version == "" {
		// Don't replace the workspace version of the main module.
		return module.Version{}, "", ""
	}
	if _, r, ok := replacement(mod, MainModules.WorkFileReplaceMap()); ok {
		return r, "", workFilePath
	}
	for _, v := range MainModules.Versions() {
		if index := MainModules.Index(v); index != nil {
			if from, r, ok := replacement(mod, index.replace); ok {
				modRoot := MainModules.ModRoot(v)
				if foundModRoot != "" && foundFrom != from && found != r {
					base.Errorf("conflicting replacements found for %v in workspace modules defined by %v and %v",
						mod, modFilePath(foundModRoot), modFilePath(modRoot))
					return found, foundModRoot, modFilePath(foundModRoot)
				}
				found, foundModRoot = r, modRoot
			}
		}
	}
	return found, foundModRoot, modFilePath(foundModRoot)
}

func replaceRelativeTo() string {
	if workFilePath := WorkFilePath(); workFilePath != "" {
		return filepath.Dir(workFilePath)
	}
	return MainModules.ModRoot(MainModules.mustGetSingleMainModule())
}

// canonicalizeReplacePath ensures that relative, on-disk, replaced module paths
// are relative to the workspace directory (in workspace mode) or to the module's
// directory (in module mode, as they already are).
func canonicalizeReplacePath(r module.Version, modRoot string) module.Version {
	if filepath.IsAbs(r.Path) || r.Version != "" || modRoot == "" {
		return r
	}
	workFilePath := WorkFilePath()
	if workFilePath == "" {
		return r
	}
	abs := filepath.Join(modRoot, r.Path)
	if rel, err := filepath.Rel(filepath.Dir(workFilePath), abs); err == nil {
		return module.Version{Path: ToDirectoryPath(rel), Version: r.Version}
	}
	// We couldn't make the version's path relative to the workspace's path,
	// so just return the absolute path. It's the best we can do.
	return module.Version{Path: ToDirectoryPath(abs), Version: r.Version}
}

// resolveReplacement returns the module actually used to load the source code
// for m: either m itself, or the replacement for m (iff m is replaced).
// It also returns the modroot of the module providing the replacement if
// one was found.
func resolveReplacement(m module.Version) module.Version {
	if r := Replacement(m); r.Path != "" {
		return r
	}
	return m
}

func toReplaceMap(replacements []*modfile.Replace) map[module.Version]module.Version {
	replaceMap := make(map[module.Version]module.Version, len(replacements))
	for _, r := range replacements {
		if prev, dup := replaceMap[r.Old]; dup && prev != r.New {
			base.Fatalf("go: conflicting replacements for %v:\n\t%v\n\t%v", r.Old, prev, r.New)
		}
		replaceMap[r.Old] = r.New
	}
	return replaceMap
}

// indexModFile rebuilds the index of modFile.
// If modFile has been changed since it was first read,
// modFile.Cleanup must be called before indexModFile.
func indexModFile(data []byte, modFile *modfile.File, mod module.Version, needsFix bool) *modFileIndex {
	i := new(modFileIndex)
	i.data = data
	i.dataNeedsFix = needsFix

	i.module = module.Version{}
	if modFile.Module != nil {
		i.module = modFile.Module.Mod
	}

	i.goVersion = ""
	if modFile.Go == nil {
		rawGoVersion.Store(mod, "")
	} else {
		i.goVersion = modFile.Go.Version
		rawGoVersion.Store(mod, modFile.Go.Version)
	}
	if modFile.Toolchain != nil {
		i.toolchain = modFile.Toolchain.Name
	}

	i.require = make(map[module.Version]requireMeta, len(modFile.Require))
	for _, r := range modFile.Require {
		i.require[r.Mod] = requireMeta{indirect: r.Indirect}
	}

	i.replace = toReplaceMap(modFile.Replace)

	i.exclude = make(map[module.Version]bool, len(modFile.Exclude))
	for _, x := range modFile.Exclude {
		i.exclude[x.Mod] = true
	}

	return i
}

// modFileIsDirty reports whether the go.mod file differs meaningfully
// from what was indexed.
// If modFile has been changed (even cosmetically) since it was first read,
// modFile.Cleanup must be called before modFileIsDirty.
func (i *modFileIndex) modFileIsDirty(modFile *modfile.File) bool {
	if i == nil {
		return modFile != nil
	}

	if i.dataNeedsFix {
		return true
	}

	if modFile.Module == nil {
		if i.module != (module.Version{}) {
			return true
		}
	} else if modFile.Module.Mod != i.module {
		return true
	}

	var goV, toolchain string
	if modFile.Go != nil {
		goV = modFile.Go.Version
	}
	if modFile.Toolchain != nil {
		toolchain = modFile.Toolchain.Name
	}

	if goV != i.goVersion ||
		toolchain != i.toolchain ||
		len(modFile.Require) != len(i.require) ||
		len(modFile.Replace) != len(i.replace) ||
		len(modFile.Exclude) != len(i.exclude) {
		return true
	}

	for _, r := range modFile.Require {
		if meta, ok := i.require[r.Mod]; !ok {
			return true
		} else if r.Indirect != meta.indirect {
			if cfg.BuildMod == "readonly" {
				// The module's requirements are consistent; only the "// indirect"
				// comments that are wrong. But those are only guaranteed to be accurate
				// after a "go mod tidy" — it's a good idea to run those before
				// committing a change, but it's certainly not mandatory.
			} else {
				return true
			}
		}
	}

	for _, r := range modFile.Replace {
		if r.New != i.replace[r.Old] {
			return true
		}
	}

	for _, x := range modFile.Exclude {
		if !i.exclude[x.Mod] {
			return true
		}
	}

	return false
}

// rawGoVersion records the Go version parsed from each module's go.mod file.
//
// If a module is replaced, the version of the replacement is keyed by the
// replacement module.Version, not the version being replaced.
var rawGoVersion sync.Map // map[module.Version]string

// A modFileSummary is a summary of a go.mod file for which we do not need to
// retain complete information — for example, the go.mod file of a dependency
// module.
type modFileSummary struct {
	module     module.Version
	goVersion  string
	toolchain  string
	pruning    modPruning
	require    []module.Version
	retract    []retraction
	deprecated string
}

// A retraction consists of a retracted version interval and rationale.
// retraction is like modfile.Retract, but it doesn't point to the syntax tree.
type retraction struct {
	modfile.VersionInterval
	Rationale string
}

// goModSummary returns a summary of the go.mod file for module m,
// taking into account any replacements for m, exclusions of its dependencies,
// and/or vendoring.
//
// m must be a version in the module graph, reachable from the Target module.
// In readonly mode, the go.sum file must contain an entry for m's go.mod file
// (or its replacement). goModSummary must not be called for the Target module
// itself, as its requirements may change. Use rawGoModSummary for other
// module versions.
//
// The caller must not modify the returned summary.
func goModSummary(m module.Version) (*modFileSummary, error) {
	if m.Version == "" && !inWorkspaceMode() && MainModules.Contains(m.Path) {
		panic("internal error: goModSummary called on a main module")
	}
	if gover.IsToolchain(m.Path) {
		return rawGoModSummary(m)
	}

	if cfg.BuildMod == "vendor" {
		summary := &modFileSummary{
			module: module.Version{Path: m.Path},
		}

		readVendorList(VendorDir())
		if vendorVersion[m.Path] != m.Version {
			// This module is not vendored, so packages cannot be loaded from it and
			// it cannot be relevant to the build.
			return summary, nil
		}

		// For every module other than the target,
		// return the full list of modules from modules.txt.
		// We don't know what versions the vendored module actually relies on,
		// so assume that it requires everything.
		summary.require = vendorList
		return summary, nil
	}

	actual := resolveReplacement(m)
	if mustHaveSums() && actual.Version != "" {
		key := module.Version{Path: actual.Path, Version: actual.Version + "/go.mod"}
		if !modfetch.HaveSum(key) {
			suggestion := fmt.Sprintf(" for go.mod file; to add it:\n\tgo mod download %s", m.Path)
			return nil, module.VersionError(actual, &sumMissingError{suggestion: suggestion})
		}
	}
	summary, err := rawGoModSummary(actual)
	if err != nil {
		return nil, err
	}

	if actual.Version == "" {
		// The actual module is a filesystem-local replacement, for which we have
		// unfortunately not enforced any sort of invariants about module lines or
		// matching module paths. Anything goes.
		//
		// TODO(bcmills): Remove this special-case, update tests, and add a
		// release note.
	} else {
		if summary.module.Path == "" {
			return nil, module.VersionError(actual, errors.New("parsing go.mod: missing module line"))
		}

		// In theory we should only allow mpath to be unequal to m.Path here if the
		// version that we fetched lacks an explicit go.mod file: if the go.mod file
		// is explicit, then it should match exactly (to ensure that imports of other
		// packages within the module are interpreted correctly). Unfortunately, we
		// can't determine that information from the module proxy protocol: we'll have
		// to leave that validation for when we load actual packages from within the
		// module.
		if mpath := summary.module.Path; mpath != m.Path && mpath != actual.Path {
			return nil, module.VersionError(actual,
				fmt.Errorf("parsing go.mod:\n"+
					"\tmodule declares its path as: %s\n"+
					"\t        but was required as: %s", mpath, m.Path))
		}
	}

	for _, mainModule := range MainModules.Versions() {
		if index := MainModules.Index(mainModule); index != nil && len(index.exclude) > 0 {
			// Drop any requirements on excluded versions.
			// Don't modify the cached summary though, since we might need the raw
			// summary separately.
			haveExcludedReqs := false
			for _, r := range summary.require {
				if index.exclude[r] {
					haveExcludedReqs = true
					break
				}
			}
			if haveExcludedReqs {
				s := new(modFileSummary)
				*s = *summary
				s.require = make([]module.Version, 0, len(summary.require))
				for _, r := range summary.require {
					if !index.exclude[r] {
						s.require = append(s.require, r)
					}
				}
				summary = s
			}
		}
	}
	return summary, nil
}

// rawGoModSummary returns a new summary of the go.mod file for module m,
// ignoring all replacements that may apply to m and excludes that may apply to
// its dependencies.
//
// rawGoModSummary cannot be used on the main module outside of workspace mode.
// The modFileSummary can still be used for retractions and deprecations
// even if a TooNewError is returned.
func rawGoModSummary(m module.Version) (*modFileSummary, error) {
	if gover.IsToolchain(m.Path) {
		if m.Path == "go" && gover.Compare(m.Version, gover.GoStrictVersion) >= 0 {
			// Declare that go 1.21.3 requires toolchain 1.21.3,
			// so that go get knows that downgrading toolchain implies downgrading go
			// and similarly upgrading go requires upgrading the toolchain.
			return &modFileSummary{module: m, require: []module.Version{{Path: "toolchain", Version: "go" + m.Version}}}, nil
		}
		return &modFileSummary{module: m}, nil
	}
	if m.Version == "" && !inWorkspaceMode() && MainModules.Contains(m.Path) {
		// Calling rawGoModSummary implies that we are treating m as a module whose
		// requirements aren't the roots of the module graph and can't be modified.
		//
		// If we are not in workspace mode, then the requirements of the main module
		// are the roots of the module graph and we expect them to be kept consistent.
		panic("internal error: rawGoModSummary called on a main module")
	}
	if m.Version == "" && inWorkspaceMode() && m.Path == "command-line-arguments" {
		// "go work sync" calls LoadModGraph to make sure the module graph is valid.
		// If there are no modules in the workspace, we synthesize an empty
		// command-line-arguments module, which rawGoModData cannot read a go.mod for.
		return &modFileSummary{module: m}, nil
	}
	return rawGoModSummaryCache.Do(m, func() (*modFileSummary, error) {
		summary := new(modFileSummary)
		name, data, err := rawGoModData(m)
		if err != nil {
			return nil, err
		}
		f, err := modfile.ParseLax(name, data, nil)
		if err != nil {
			return nil, module.VersionError(m, fmt.Errorf("parsing %s: %v", base.ShortPath(name), err))
		}
		if f.Module != nil {
			summary.module = f.Module.Mod
			summary.deprecated = f.Module.Deprecated
		}
		if f.Go != nil {
			rawGoVersion.LoadOrStore(m, f.Go.Version)
			summary.goVersion = f.Go.Version
			summary.pruning = pruningForGoVersion(f.Go.Version)
		} else {
			summary.pruning = unpruned
		}
		if f.Toolchain != nil {
			summary.toolchain = f.Toolchain.Name
		}
		if len(f.Require) > 0 {
			summary.require = make([]module.Version, 0, len(f.Require)+1)
			for _, req := range f.Require {
				summary.require = append(summary.require, req.Mod)
			}
		}

		if len(f.Retract) > 0 {
			summary.retract = make([]retraction, 0, len(f.Retract))
			for _, ret := range f.Retract {
				summary.retract = append(summary.retract, retraction{
					VersionInterval: ret.VersionInterval,
					Rationale:       ret.Rationale,
				})
			}
		}

		// This block must be kept at the end of the function because the summary may
		// be used for reading retractions or deprecations even if a TooNewError is
		// returned.
		if summary.goVersion != "" && gover.Compare(summary.goVersion, gover.GoStrictVersion) >= 0 {
			summary.require = append(summary.require, module.Version{Path: "go", Version: summary.goVersion})
			if gover.Compare(summary.goVersion, gover.Local()) > 0 {
				return summary, &gover.TooNewError{What: "module " + m.String(), GoVersion: summary.goVersion}
			}
		}

		return summary, nil
	})
}

var rawGoModSummaryCache par.ErrCache[module.Version, *modFileSummary]

// rawGoModData returns the content of the go.mod file for module m, ignoring
// all replacements that may apply to m.
//
// rawGoModData cannot be used on the main module outside of workspace mode.
//
// Unlike rawGoModSummary, rawGoModData does not cache its results in memory.
// Use rawGoModSummary instead unless you specifically need these bytes.
func rawGoModData(m module.Version) (name string, data []byte, err error) {
	if m.Version == "" {
		dir := m.Path
		if !filepath.IsAbs(dir) {
			if inWorkspaceMode() && MainModules.Contains(m.Path) {
				dir = MainModules.ModRoot(m)
			} else {
				// m is a replacement module with only a file path.
				dir = filepath.Join(replaceRelativeTo(), dir)
			}
		}
		name = filepath.Join(dir, "go.mod")
		if fsys.Replaced(name) {
			// Don't lock go.mod if it's part of the overlay.
			// On Plan 9, locking requires chmod, and we don't want to modify any file
			// in the overlay. See #44700.
			data, err = os.ReadFile(fsys.Actual(name))
		} else {
			data, err = lockedfile.Read(name)
		}
		if err != nil {
			return "", nil, module.VersionError(m, fmt.Errorf("reading %s: %v", base.ShortPath(name), err))
		}
	} else {
		if !gover.ModIsValid(m.Path, m.Version) {
			// Disallow the broader queries supported by fetch.Lookup.
			base.Fatalf("go: internal error: %s@%s: unexpected invalid semantic version", m.Path, m.Version)
		}
		name = "go.mod"
		data, err = modfetch.GoMod(context.TODO(), m.Path, m.Version)
	}
	return name, data, err
}

// queryLatestVersionIgnoringRetractions looks up the latest version of the
// module with the given path without considering retracted or excluded
// versions.
//
// If all versions of the module are replaced,
// queryLatestVersionIgnoringRetractions returns the replacement without making
// a query.
//
// If the queried latest version is replaced,
// queryLatestVersionIgnoringRetractions returns the replacement.
func queryLatestVersionIgnoringRetractions(ctx context.Context, path string) (latest module.Version, err error) {
	return latestVersionIgnoringRetractionsCache.Do(path, func() (module.Version, error) {
		ctx, span := trace.StartSpan(ctx, "queryLatestVersionIgnoringRetractions "+path)
		defer span.Done()

		if repl := Replacement(module.Version{Path: path}); repl.Path != "" {
			// All versions of the module were replaced.
			// No need to query.
			return repl, nil
		}

		// Find the latest version of the module.
		// Ignore exclusions from the main module's go.mod.
		const ignoreSelected = ""
		var allowAll AllowedFunc
		rev, err := Query(ctx, path, "latest", ignoreSelected, allowAll)
		if err != nil {
			return module.Version{}, err
		}
		latest := module.Version{Path: path, Version: rev.Version}
		if repl := resolveReplacement(latest); repl.Path != "" {
			latest = repl
		}
		return latest, nil
	})
}

var latestVersionIgnoringRetractionsCache par.ErrCache[string, module.Version] // path → queryLatestVersionIgnoringRetractions result

// ToDirectoryPath adds a prefix if necessary so that path in unambiguously
// an absolute path or a relative path starting with a '.' or '..'
// path component.
func ToDirectoryPath(path string) string {
	if modfile.IsDirectoryPath(path) {
		return path
	}
	// The path is not a relative path or an absolute path, so make it relative
	// to the current directory.
	return "./" + filepath.ToSlash(filepath.Clean(path))
}
```