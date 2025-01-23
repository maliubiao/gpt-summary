Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The first step is to grasp the overall purpose of the code. The comment `// go mod edit` and the `UsageLine` immediately tell us this is about editing `go.mod` files. The `Short` description reinforces this: "edit go.mod from tools or scripts."  This implies it's designed for programmatic manipulation, not direct human interaction as much as other `go mod` commands.

2. **Identify Key Components:** Scan the code for important elements:
    * **Package Declaration:** `package modcmd` - This tells us the code belongs to the `modcmd` package, likely within the `cmd/go` tool.
    * **Imports:** Look at the imported packages. These give clues about the functionalities used:
        * `bytes`, `context`, `encoding/json`, `errors`, `fmt`, `os`, `strings`: Basic Go utilities.
        * `cmd/go/internal/base`: Core functionalities of the `go` command.
        * `cmd/go/internal/gover`: Handling Go versions.
        * `cmd/go/internal/lockedfile`: Safe file operations, likely for concurrent access.
        * `cmd/go/internal/modfetch`: Interacting with module sources.
        * `cmd/go/internal/modload`: Loading and managing modules.
        * `golang.org/x/mod/modfile`:  *This is crucial*. It's the library for parsing and manipulating `go.mod` files.
        * `golang.org/x/mod/module`: Represents module identity.
    * **Global Variables:**  `cmdEdit`, `editFmt`, `editGo`, etc. These look like flags and the main command structure. `edits` being a slice of functions is interesting – likely used to accumulate editing operations.
    * **`init()` Function:** This function sets up the command, registering flags and associating the `runEdit` function.
    * **`runEdit()` Function:** This is the core logic. It processes arguments and flags, reads the `go.mod` file, applies edits, and writes the result.
    * **Helper Functions:** Functions like `parsePathVersion`, `flagGodebug`, `editPrintJSON`, etc., handle specific flag parsing and actions.
    * **Data Structures:** `fileJSON`, `requireJSON`, etc., define the JSON output format.

3. **Map Flags to Functionality:** Go through each flag defined in `cmdEdit.Flag.Bool`, `cmdEdit.Flag.String`, and the `cmdEdit.Flag.Var` calls. For each flag, understand its purpose based on its name and the associated helper function:
    * `-fmt`: Formatting.
    * `-module`: Changing the module path.
    * `-go`: Setting the Go version.
    * `-toolchain`: Setting the toolchain version.
    * `-json`, `-print`: Output formats.
    * `-godebug`, `-dropgodebug`, `-require`, `-droprequire`, `-exclude`, `-dropexclude`, `-replace`, `-dropreplace`, `-retract`, `-dropretract`, `-tool`, `-droptool`:  Various editing operations on `go.mod` entries.

4. **Trace the `runEdit()` Logic:** Follow the execution flow of the `runEdit` function:
    * **Flag Validation:** Checks if any flags are provided and handles conflicting flags (`-json` and `-print`).
    * **Argument Handling:** Determines the target `go.mod` file.
    * **Input Validation:** Validates `-module`, `-go`, and `-toolchain` values.
    * **File Reading:** Reads the `go.mod` file.
    * **Parsing:** Parses the `go.mod` content using `modfile.Parse`.
    * **Applying Direct Flag Changes:** Handles `-module`, `-go`, and `-toolchain` directly.
    * **Applying Accumulated Edits:** Iterates through the `edits` slice and calls the corresponding functions to modify the `modfile.File` structure.
    * **Formatting and Cleanup:** Sorts and cleans up the `go.mod` structure.
    * **Output:** Either prints to stdout (`-print`), prints as JSON (`-json`), or writes back to the file. It also includes logic to prevent overwriting if the file has changed concurrently.

5. **Infer Go Language Features:** Based on the functionality, identify the Go language features being manipulated:
    * **Module Path:** The `module` directive in `go.mod`.
    * **Go Version:** The `go` directive.
    * **Toolchain Version:** The `toolchain` directive.
    * **Dependencies:** The `require` directive.
    * **Exclusions:** The `exclude` directive.
    * **Replacements:** The `replace` directive.
    * **Retractions:** The `retract` directive.
    * **Tools:** The `tool` directive.
    * **`godebug`:**  A less common directive for controlling runtime debugging.

6. **Construct Examples:** For each feature, create Go code examples that demonstrate how the `go mod edit` command would affect the `go.mod` file. Consider different scenarios, including adding, removing, and modifying entries. Include the *assumptions* about the initial `go.mod` and the *expected output*.

7. **Identify Command-Line Parameter Handling:** Focus on how the flags are parsed and how the arguments are interpreted. Pay attention to functions like `parsePathVersion`, `parsePath`, and `parseVersionInterval`, which handle the specific formats of flag values.

8. **Spot Potential User Errors:** Think about common mistakes users might make when using this command, especially if they are not fully aware of the underlying `go.mod` structure or the precise syntax of the flags. Consider cases like incorrect flag usage, invalid version formats, or misunderstanding the difference between `-replace` with and without versions.

9. **Structure the Output:** Organize the information logically, starting with a summary of the functionality, then providing detailed explanations for each aspect (Go features, examples, command-line parameters, common errors). Use clear headings and formatting to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus heavily on the internal workings of `modfile`.
* **Correction:** Shift focus to the *user-facing functionality* of `go mod edit`. The code is the implementation, but the user cares about what the command *does*.
* **Initial thought:**  Try to explain every single line of code.
* **Correction:** Focus on the *major functionalities* and how the code achieves them. Details of the `lockedfile` package, for instance, are less important for a general understanding of `go mod edit`.
* **Initial thought:**  Just list the flags and their descriptions.
* **Correction:**  Provide *examples* of how to use the flags and what the effect on `go.mod` is. This makes the explanation much more practical.

By following this systematic approach, you can effectively analyze and explain the functionality of a complex piece of code like the `go mod edit` implementation.
这段代码是 Go 语言 `go` 命令的一个子命令 `go mod edit` 的实现。它的主要功能是通过命令行接口编辑 `go.mod` 文件，主要供工具或脚本使用。它直接操作 `go.mod` 文件，不涉及模块的解析和查找。

以下是 `go mod edit` 的主要功能点：

**1. 格式化 `go.mod` 文件 (`-fmt`)**

*   **功能:**  重新格式化 `go.mod` 文件，使其符合标准的 Go module 格式。
*   **代码示例:**
    ```bash
    go mod edit -fmt
    ```
*   **假设输入 (go.mod):**
    ```
    module  example.com/hello

    go 1.16

    require golang.org/x/text v0.3.0
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    require golang.org/x/text v0.3.0
    ```
    (在这个简单例子中，格式可能没有明显变化，但 `go mod edit -fmt` 会确保缩进、空行等符合规范)

**2. 修改模块路径 (`-module`)**

*   **功能:**  修改 `go.mod` 文件中的 `module` 行，即更改模块的导入路径。
*   **代码示例:**
    ```bash
    go mod edit -module example.org/newname
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/oldname

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.org/newname

    go 1.16
    ```

**3. 添加或替换 `godebug` 设置 (`-godebug`)**

*   **功能:**  在 `go.mod` 文件中添加或替换 `godebug` 行。用于设置运行时调试选项。
*   **代码示例:**
    ```bash
    go mod edit -godebug=http2debug=2
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    godebug http2debug=2
    ```
*   **假设输入 (go.mod) (存在相同的 key):**
    ```
    module example.com/hello

    go 1.16

    godebug http2debug=1
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    godebug http2debug=2
    ```

**4. 删除 `godebug` 设置 (`-dropgodebug`)**

*   **功能:**  从 `go.mod` 文件中删除指定的 `godebug` 行。
*   **代码示例:**
    ```bash
    go mod edit -dropgodebug=http2debug
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    godebug http2debug=2
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```

**5. 添加或替换依赖 (`-require`)**

*   **功能:**  向 `go.mod` 文件中添加一个新的依赖项，或者更新已存在的依赖项的版本。它会覆盖已有的相同路径的依赖。
*   **代码示例:**
    ```bash
    go mod edit -require=github.com/gin-gonic/gin@v1.7.7
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    require github.com/gin-gonic/gin v1.7.7
    ```
*   **假设输入 (go.mod) (已存在相同依赖):**
    ```
    module example.com/hello

    go 1.16

    require github.com/gin-gonic/gin v1.6.0
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    require github.com/gin-gonic/gin v1.7.7
    ```

**6. 删除依赖 (`-droprequire`)**

*   **功能:**  从 `go.mod` 文件中删除指定的依赖项。
*   **代码示例:**
    ```bash
    go mod edit -droprequire=github.com/gin-gonic/gin
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    require github.com/gin-gonic/gin v1.7.7
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```

**7. 设置 Go 语言版本 (`-go`)**

*   **功能:**  设置 `go.mod` 文件中声明的 Go 语言版本。
*   **代码示例:**
    ```bash
    go mod edit -go=1.17
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.17
    ```
*   **代码示例 (删除 go 版本声明):**
    ```bash
    go mod edit -go=none
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello
    ```

**8. 设置 Go 工具链版本 (`-toolchain`)**

*   **功能:**  设置 `go.mod` 文件中声明的 Go 工具链版本。
*   **代码示例:**
    ```bash
    go mod edit -toolchain=go1.21beta1
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.20
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.20

    toolchain go1.21beta1
    ```
*   **代码示例 (删除 toolchain 版本声明):**
    ```bash
    go mod edit -toolchain=none
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.20

    toolchain go1.21beta1
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.20
    ```

**9. 添加排除项 (`-exclude`)**

*   **功能:**  在 `go.mod` 文件中添加一个排除项，阻止使用特定模块的特定版本。
*   **代码示例:**
    ```bash
    go mod edit -exclude=golang.org/x/text@v0.3.1
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    exclude golang.org/x/text v0.3.1
    ```

**10. 删除排除项 (`-dropexclude`)**

*   **功能:**  从 `go.mod` 文件中删除指定的排除项。
*   **代码示例:**
    ```bash
    go mod edit -dropexclude=golang.org/x/text@v0.3.1
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    exclude golang.org/x/text v0.3.1
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```

**11. 添加替换项 (`-replace`)**

*   **功能:**  在 `go.mod` 文件中添加一个替换项，将对某个模块特定版本或所有版本的引用重定向到另一个模块或本地路径。
*   **代码示例 (替换特定版本):**
    ```bash
    go mod edit -replace=example.com/old@v1.0.0=example.com/new@v2.0.0
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    replace example.com/old v1.0.0 => example.com/new v2.0.0
    ```
*   **代码示例 (替换所有版本为本地路径):**
    ```bash
    go mod edit -replace=example.com/old=./local/replacement
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    replace example.com/old => ./local/replacement
    ```

**12. 删除替换项 (`-dropreplace`)**

*   **功能:**  从 `go.mod` 文件中删除指定的替换项。
*   **代码示例 (删除特定版本的替换):**
    ```bash
    go mod edit -dropreplace=example.com/old@v1.0.0
    ```
*   **代码示例 (删除所有版本的替换):**
    ```bash
    go mod edit -dropreplace=example.com/old
    ```

**13. 添加撤回声明 (`-retract`)**

*   **功能:**  在 `go.mod` 文件中添加一个撤回声明，表明某些版本不应再被使用。
*   **代码示例 (撤回单个版本):**
    ```bash
    go mod edit -retract=v1.0.0
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    retract v1.0.0
    ```
*   **代码示例 (撤回版本区间):**
    ```bash
    go mod edit -retract="[v1.0.0,v1.0.5]"
    ```

**14. 删除撤回声明 (`-dropretract`)**

*   **功能:**  从 `go.mod` 文件中删除指定的撤回声明。
*   **代码示例 (删除单个版本撤回):**
    ```bash
    go mod edit -dropretract=v1.0.0
    ```
*   **代码示例 (删除版本区间撤回):**
    ```bash
    go mod edit -dropretract="[v1.0.0,v1.0.5]"
    ```

**15. 添加工具声明 (`-tool`)**

*   **功能:**  在 `go.mod` 文件中添加一个工具依赖声明。
*   **代码示例:**
    ```bash
    go mod edit -tool=github.com/my/tool
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    tool github.com/my/tool
    ```

**16. 删除工具声明 (`-droptool`)**

*   **功能:**  从 `go.mod` 文件中删除指定的工具依赖声明。
*   **代码示例:**
    ```bash
    go mod edit -droptool=github.com/my/tool
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16

    tool github.com/my/tool
    ```
*   **预期输出 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```

**17. 打印 `go.mod` 内容 (`-print`)**

*   **功能:**  将修改后的 `go.mod` 文件的文本内容打印到标准输出，而不是写回文件。
*   **代码示例:**
    ```bash
    go mod edit -require=example.com/newdep@v1.0.0 -print
    ```

**18. 打印 `go.mod` 内容为 JSON (`-json`)**

*   **功能:**  将修改后的 `go.mod` 文件的内容以 JSON 格式打印到标准输出，而不是写回文件。JSON 结构对应于代码中定义的 `Module`, `GoMod`, `Require`, `Exclude`, `Replace`, `Retract` 等结构体。
*   **代码示例:**
    ```bash
    go mod edit -require=example.com/newdep@v1.0.0 -json
    ```
*   **假设输入 (go.mod):**
    ```
    module example.com/hello

    go 1.16
    ```
*   **预期输出 (标准输出):**
    ```json
    {
        "Module": {
            "Path": "example.com/hello"
        },
        "Go": "1.16",
        "Require": [
            {
                "Path": "example.com/newdep",
                "Version": "v1.0.0"
            }
        ]
    }
    ```

**命令行参数处理:**

*   `go mod edit [editing flags] [-fmt|-print|-json] [go.mod]`
*   **`editing flags`:**  如 `-module`, `-require`, `-replace` 等，用于指定要执行的编辑操作。可以多次使用来执行多个编辑操作。
*   **`-fmt`:** 格式化 `go.mod` 文件。
*   **`-print`:** 将修改后的 `go.mod` 内容打印到标准输出。
*   **`-json`:** 将修改后的 `go.mod` 内容以 JSON 格式打印到标准输出。
*   **`[go.mod]`:** 可选参数，指定要编辑的 `go.mod` 文件的路径。如果省略，则默认编辑当前目录下的 `go.mod` 文件。

**使用者易犯错的点:**

1. **忘记指定任何 flag:**  如果运行 `go mod edit` 但没有指定任何编辑 flag (`-fmt`, `-module`, `-require` 等)，会导致错误。

    ```bash
    go mod edit
    # 错误: go: no flags specified (see 'go help mod edit').
    ```

2. **同时使用 `-json` 和 `-print`:**  这两个 flag 是互斥的，不能同时使用。

    ```bash
    go mod edit -require=example.com/dep@v1.0.0 -json -print
    # 错误: go: cannot use both -json and -print
    ```

3. **`-require` 和 `-droprequire` 操作的版本问题:**  `-require` 需要指定完整的 `path@version`，而 `-droprequire` 只需要 `path`。容易混淆。

    ```bash
    go mod edit -droprequire=example.com/dep@v1.0.0  # 错误，-droprequire 只需要路径
    go mod edit -droprequire=example.com/dep
    ```

4. **`-replace` 语法的理解:**  `-replace` 的语法比较复杂，需要理解 `old[@v]=new[@v]` 的含义，特别是当省略版本时的行为。

    *   `go mod edit -replace=old=new`：将所有版本的 `old` 替换为本地路径 `new`。
    *   `go mod edit -replace=old@v1=new@v2`：将 `old` 的 `v1` 版本替换为 `new` 的 `v2` 版本。
    *   如果 `new` 部分省略版本，则应该是一个本地目录。

5. **版本号格式错误:** 在使用 `-require`, `-exclude`, `-replace` 等涉及版本号的 flag 时，需要提供正确的版本号格式。虽然代码中 `allowedVersionArg` 允许一些非语义化的版本，但在大多数情况下，最好使用符合语义化版本规范的版本号。

6. **误解 `-require` 的作用:**  `-require` 只是修改 `go.mod` 文件，不会实际下载或更新依赖。这与 `go get` 不同，`go get` 会同时修改 `go.mod` 并下载依赖。

7. **在不理解模块图的情况下使用 `-require` 和 `-replace`:** 这些 flag 主要供工具使用，手动使用时需要对模块依赖关系有清晰的理解，否则可能导致构建错误或其他问题。

总的来说，`go mod edit` 是一个强大的工具，用于以编程方式修改 `go.mod` 文件。理解其各个 flag 的作用和语法对于正确使用至关重要。

### 提示词
```
这是路径为go/src/cmd/go/internal/modcmd/edit.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// go mod edit

package modcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"cmd/go/internal/base"
	"cmd/go/internal/gover"
	"cmd/go/internal/lockedfile"
	"cmd/go/internal/modfetch"
	"cmd/go/internal/modload"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

var cmdEdit = &base.Command{
	UsageLine: "go mod edit [editing flags] [-fmt|-print|-json] [go.mod]",
	Short:     "edit go.mod from tools or scripts",
	Long: `
Edit provides a command-line interface for editing go.mod,
for use primarily by tools or scripts. It reads only go.mod;
it does not look up information about the modules involved.
By default, edit reads and writes the go.mod file of the main module,
but a different target file can be specified after the editing flags.

The editing flags specify a sequence of editing operations.

The -fmt flag reformats the go.mod file without making other changes.
This reformatting is also implied by any other modifications that use or
rewrite the go.mod file. The only time this flag is needed is if no other
flags are specified, as in 'go mod edit -fmt'.

The -module flag changes the module's path (the go.mod file's module line).

The -godebug=key=value flag adds a godebug key=value line,
replacing any existing godebug lines with the given key.

The -dropgodebug=key flag drops any existing godebug lines
with the given key.

The -require=path@version and -droprequire=path flags
add and drop a requirement on the given module path and version.
Note that -require overrides any existing requirements on path.
These flags are mainly for tools that understand the module graph.
Users should prefer 'go get path@version' or 'go get path@none',
which make other go.mod adjustments as needed to satisfy
constraints imposed by other modules.

The -go=version flag sets the expected Go language version.
This flag is mainly for tools that understand Go version dependencies.
Users should prefer 'go get go@version'.

The -toolchain=version flag sets the Go toolchain to use.
This flag is mainly for tools that understand Go version dependencies.
Users should prefer 'go get toolchain@version'.

The -exclude=path@version and -dropexclude=path@version flags
add and drop an exclusion for the given module path and version.
Note that -exclude=path@version is a no-op if that exclusion already exists.

The -replace=old[@v]=new[@v] flag adds a replacement of the given
module path and version pair. If the @v in old@v is omitted, a
replacement without a version on the left side is added, which applies
to all versions of the old module path. If the @v in new@v is omitted,
the new path should be a local module root directory, not a module
path. Note that -replace overrides any redundant replacements for old[@v],
so omitting @v will drop existing replacements for specific versions.

The -dropreplace=old[@v] flag drops a replacement of the given
module path and version pair. If the @v is omitted, a replacement without
a version on the left side is dropped.

The -retract=version and -dropretract=version flags add and drop a
retraction on the given version. The version may be a single version
like "v1.2.3" or a closed interval like "[v1.1.0,v1.1.9]". Note that
-retract=version is a no-op if that retraction already exists.

The -tool=path and -droptool=path flags add and drop a tool declaration
for the given path.

The -godebug, -dropgodebug, -require, -droprequire, -exclude, -dropexclude,
-replace, -dropreplace, -retract, -dropretract, -tool, and -droptool editing
flags may be repeated, and the changes are applied in the order given.

The -print flag prints the final go.mod in its text format instead of
writing it back to go.mod.

The -json flag prints the final go.mod file in JSON format instead of
writing it back to go.mod. The JSON output corresponds to these Go types:

	type Module struct {
		Path    string
		Version string
	}

	type GoMod struct {
		Module    ModPath
		Go        string
		Toolchain string
		Godebug   []Godebug
		Require   []Require
		Exclude   []Module
		Replace   []Replace
		Retract   []Retract
	}

	type ModPath struct {
		Path       string
		Deprecated string
	}

	type Godebug struct {
		Key   string
		Value string
	}

	type Require struct {
		Path     string
		Version  string
		Indirect bool
	}

	type Replace struct {
		Old Module
		New Module
	}

	type Retract struct {
		Low       string
		High      string
		Rationale string
	}

	type Tool struct {
		Path string
	}

Retract entries representing a single version (not an interval) will have
the "Low" and "High" fields set to the same value.

Note that this only describes the go.mod file itself, not other modules
referred to indirectly. For the full set of modules available to a build,
use 'go list -m -json all'.

Edit also provides the -C, -n, and -x build flags.

See https://golang.org/ref/mod#go-mod-edit for more about 'go mod edit'.
	`,
}

var (
	editFmt       = cmdEdit.Flag.Bool("fmt", false, "")
	editGo        = cmdEdit.Flag.String("go", "", "")
	editToolchain = cmdEdit.Flag.String("toolchain", "", "")
	editJSON      = cmdEdit.Flag.Bool("json", false, "")
	editPrint     = cmdEdit.Flag.Bool("print", false, "")
	editModule    = cmdEdit.Flag.String("module", "", "")
	edits         []func(*modfile.File) // edits specified in flags
)

type flagFunc func(string)

func (f flagFunc) String() string     { return "" }
func (f flagFunc) Set(s string) error { f(s); return nil }

func init() {
	cmdEdit.Run = runEdit // break init cycle

	cmdEdit.Flag.Var(flagFunc(flagGodebug), "godebug", "")
	cmdEdit.Flag.Var(flagFunc(flagDropGodebug), "dropgodebug", "")
	cmdEdit.Flag.Var(flagFunc(flagRequire), "require", "")
	cmdEdit.Flag.Var(flagFunc(flagDropRequire), "droprequire", "")
	cmdEdit.Flag.Var(flagFunc(flagExclude), "exclude", "")
	cmdEdit.Flag.Var(flagFunc(flagDropExclude), "dropexclude", "")
	cmdEdit.Flag.Var(flagFunc(flagReplace), "replace", "")
	cmdEdit.Flag.Var(flagFunc(flagDropReplace), "dropreplace", "")
	cmdEdit.Flag.Var(flagFunc(flagRetract), "retract", "")
	cmdEdit.Flag.Var(flagFunc(flagDropRetract), "dropretract", "")
	cmdEdit.Flag.Var(flagFunc(flagTool), "tool", "")
	cmdEdit.Flag.Var(flagFunc(flagDropTool), "droptool", "")

	base.AddBuildFlagsNX(&cmdEdit.Flag)
	base.AddChdirFlag(&cmdEdit.Flag)
	base.AddModCommonFlags(&cmdEdit.Flag)
}

func runEdit(ctx context.Context, cmd *base.Command, args []string) {
	anyFlags := *editModule != "" ||
		*editGo != "" ||
		*editToolchain != "" ||
		*editJSON ||
		*editPrint ||
		*editFmt ||
		len(edits) > 0

	if !anyFlags {
		base.Fatalf("go: no flags specified (see 'go help mod edit').")
	}

	if *editJSON && *editPrint {
		base.Fatalf("go: cannot use both -json and -print")
	}

	if len(args) > 1 {
		base.Fatalf("go: too many arguments")
	}
	var gomod string
	if len(args) == 1 {
		gomod = args[0]
	} else {
		gomod = modload.ModFilePath()
	}

	if *editModule != "" {
		if err := module.CheckImportPath(*editModule); err != nil {
			base.Fatalf("go: invalid -module: %v", err)
		}
	}

	if *editGo != "" && *editGo != "none" {
		if !modfile.GoVersionRE.MatchString(*editGo) {
			base.Fatalf(`go mod: invalid -go option; expecting something like "-go %s"`, gover.Local())
		}
	}
	if *editToolchain != "" && *editToolchain != "none" {
		if !modfile.ToolchainRE.MatchString(*editToolchain) {
			base.Fatalf(`go mod: invalid -toolchain option; expecting something like "-toolchain go%s"`, gover.Local())
		}
	}

	data, err := lockedfile.Read(gomod)
	if err != nil {
		base.Fatal(err)
	}

	modFile, err := modfile.Parse(gomod, data, nil)
	if err != nil {
		base.Fatalf("go: errors parsing %s:\n%s", base.ShortPath(gomod), err)
	}

	if *editModule != "" {
		modFile.AddModuleStmt(*editModule)
	}

	if *editGo == "none" {
		modFile.DropGoStmt()
	} else if *editGo != "" {
		if err := modFile.AddGoStmt(*editGo); err != nil {
			base.Fatalf("go: internal error: %v", err)
		}
	}
	if *editToolchain == "none" {
		modFile.DropToolchainStmt()
	} else if *editToolchain != "" {
		if err := modFile.AddToolchainStmt(*editToolchain); err != nil {
			base.Fatalf("go: internal error: %v", err)
		}
	}

	if len(edits) > 0 {
		for _, edit := range edits {
			edit(modFile)
		}
	}
	modFile.SortBlocks()
	modFile.Cleanup() // clean file after edits

	if *editJSON {
		editPrintJSON(modFile)
		return
	}

	out, err := modFile.Format()
	if err != nil {
		base.Fatal(err)
	}

	if *editPrint {
		os.Stdout.Write(out)
		return
	}

	// Make a best-effort attempt to acquire the side lock, only to exclude
	// previous versions of the 'go' command from making simultaneous edits.
	if unlock, err := modfetch.SideLock(ctx); err == nil {
		defer unlock()
	}

	err = lockedfile.Transform(gomod, func(lockedData []byte) ([]byte, error) {
		if !bytes.Equal(lockedData, data) {
			return nil, errors.New("go.mod changed during editing; not overwriting")
		}
		return out, nil
	})
	if err != nil {
		base.Fatal(err)
	}
}

// parsePathVersion parses -flag=arg expecting arg to be path@version.
func parsePathVersion(flag, arg string) (path, version string) {
	before, after, found := strings.Cut(arg, "@")
	if !found {
		base.Fatalf("go: -%s=%s: need path@version", flag, arg)
	}
	path, version = strings.TrimSpace(before), strings.TrimSpace(after)
	if err := module.CheckImportPath(path); err != nil {
		base.Fatalf("go: -%s=%s: invalid path: %v", flag, arg, err)
	}

	if !allowedVersionArg(version) {
		base.Fatalf("go: -%s=%s: invalid version %q", flag, arg, version)
	}

	return path, version
}

// parsePath parses -flag=arg expecting arg to be path (not path@version).
func parsePath(flag, arg string) (path string) {
	if strings.Contains(arg, "@") {
		base.Fatalf("go: -%s=%s: need just path, not path@version", flag, arg)
	}
	path = arg
	if err := module.CheckImportPath(path); err != nil {
		base.Fatalf("go: -%s=%s: invalid path: %v", flag, arg, err)
	}
	return path
}

// parsePathVersionOptional parses path[@version], using adj to
// describe any errors.
func parsePathVersionOptional(adj, arg string, allowDirPath bool) (path, version string, err error) {
	if allowDirPath && modfile.IsDirectoryPath(arg) {
		return arg, "", nil
	}
	before, after, found := strings.Cut(arg, "@")
	if !found {
		path = arg
	} else {
		path, version = strings.TrimSpace(before), strings.TrimSpace(after)
	}
	if err := module.CheckImportPath(path); err != nil {
		return path, version, fmt.Errorf("invalid %s path: %v", adj, err)
	}
	if path != arg && !allowedVersionArg(version) {
		return path, version, fmt.Errorf("invalid %s version: %q", adj, version)
	}
	return path, version, nil
}

// parseVersionInterval parses a single version like "v1.2.3" or a closed
// interval like "[v1.2.3,v1.4.5]". Note that a single version has the same
// representation as an interval with equal upper and lower bounds: both
// Low and High are set.
func parseVersionInterval(arg string) (modfile.VersionInterval, error) {
	if !strings.HasPrefix(arg, "[") {
		if !allowedVersionArg(arg) {
			return modfile.VersionInterval{}, fmt.Errorf("invalid version: %q", arg)
		}
		return modfile.VersionInterval{Low: arg, High: arg}, nil
	}
	if !strings.HasSuffix(arg, "]") {
		return modfile.VersionInterval{}, fmt.Errorf("invalid version interval: %q", arg)
	}
	s := arg[1 : len(arg)-1]
	before, after, found := strings.Cut(s, ",")
	if !found {
		return modfile.VersionInterval{}, fmt.Errorf("invalid version interval: %q", arg)
	}
	low := strings.TrimSpace(before)
	high := strings.TrimSpace(after)
	if !allowedVersionArg(low) || !allowedVersionArg(high) {
		return modfile.VersionInterval{}, fmt.Errorf("invalid version interval: %q", arg)
	}
	return modfile.VersionInterval{Low: low, High: high}, nil
}

// allowedVersionArg returns whether a token may be used as a version in go.mod.
// We don't call modfile.CheckPathVersion, because that insists on versions
// being in semver form, but here we want to allow versions like "master" or
// "1234abcdef", which the go command will resolve the next time it runs (or
// during -fix).  Even so, we need to make sure the version is a valid token.
func allowedVersionArg(arg string) bool {
	return !modfile.MustQuote(arg)
}

// flagGodebug implements the -godebug flag.
func flagGodebug(arg string) {
	key, value, ok := strings.Cut(arg, "=")
	if !ok || strings.ContainsAny(arg, "\"`',") {
		base.Fatalf("go: -godebug=%s: need key=value", arg)
	}
	edits = append(edits, func(f *modfile.File) {
		if err := f.AddGodebug(key, value); err != nil {
			base.Fatalf("go: -godebug=%s: %v", arg, err)
		}
	})
}

// flagDropGodebug implements the -dropgodebug flag.
func flagDropGodebug(arg string) {
	edits = append(edits, func(f *modfile.File) {
		if err := f.DropGodebug(arg); err != nil {
			base.Fatalf("go: -dropgodebug=%s: %v", arg, err)
		}
	})
}

// flagRequire implements the -require flag.
func flagRequire(arg string) {
	path, version := parsePathVersion("require", arg)
	edits = append(edits, func(f *modfile.File) {
		if err := f.AddRequire(path, version); err != nil {
			base.Fatalf("go: -require=%s: %v", arg, err)
		}
	})
}

// flagDropRequire implements the -droprequire flag.
func flagDropRequire(arg string) {
	path := parsePath("droprequire", arg)
	edits = append(edits, func(f *modfile.File) {
		if err := f.DropRequire(path); err != nil {
			base.Fatalf("go: -droprequire=%s: %v", arg, err)
		}
	})
}

// flagExclude implements the -exclude flag.
func flagExclude(arg string) {
	path, version := parsePathVersion("exclude", arg)
	edits = append(edits, func(f *modfile.File) {
		if err := f.AddExclude(path, version); err != nil {
			base.Fatalf("go: -exclude=%s: %v", arg, err)
		}
	})
}

// flagDropExclude implements the -dropexclude flag.
func flagDropExclude(arg string) {
	path, version := parsePathVersion("dropexclude", arg)
	edits = append(edits, func(f *modfile.File) {
		if err := f.DropExclude(path, version); err != nil {
			base.Fatalf("go: -dropexclude=%s: %v", arg, err)
		}
	})
}

// flagReplace implements the -replace flag.
func flagReplace(arg string) {
	before, after, found := strings.Cut(arg, "=")
	if !found {
		base.Fatalf("go: -replace=%s: need old[@v]=new[@w] (missing =)", arg)
	}
	old, new := strings.TrimSpace(before), strings.TrimSpace(after)
	if strings.HasPrefix(new, ">") {
		base.Fatalf("go: -replace=%s: separator between old and new is =, not =>", arg)
	}
	oldPath, oldVersion, err := parsePathVersionOptional("old", old, false)
	if err != nil {
		base.Fatalf("go: -replace=%s: %v", arg, err)
	}
	newPath, newVersion, err := parsePathVersionOptional("new", new, true)
	if err != nil {
		base.Fatalf("go: -replace=%s: %v", arg, err)
	}
	if newPath == new && !modfile.IsDirectoryPath(new) {
		base.Fatalf("go: -replace=%s: unversioned new path must be local directory", arg)
	}

	edits = append(edits, func(f *modfile.File) {
		if err := f.AddReplace(oldPath, oldVersion, newPath, newVersion); err != nil {
			base.Fatalf("go: -replace=%s: %v", arg, err)
		}
	})
}

// flagDropReplace implements the -dropreplace flag.
func flagDropReplace(arg string) {
	path, version, err := parsePathVersionOptional("old", arg, true)
	if err != nil {
		base.Fatalf("go: -dropreplace=%s: %v", arg, err)
	}
	edits = append(edits, func(f *modfile.File) {
		if err := f.DropReplace(path, version); err != nil {
			base.Fatalf("go: -dropreplace=%s: %v", arg, err)
		}
	})
}

// flagRetract implements the -retract flag.
func flagRetract(arg string) {
	vi, err := parseVersionInterval(arg)
	if err != nil {
		base.Fatalf("go: -retract=%s: %v", arg, err)
	}
	edits = append(edits, func(f *modfile.File) {
		if err := f.AddRetract(vi, ""); err != nil {
			base.Fatalf("go: -retract=%s: %v", arg, err)
		}
	})
}

// flagDropRetract implements the -dropretract flag.
func flagDropRetract(arg string) {
	vi, err := parseVersionInterval(arg)
	if err != nil {
		base.Fatalf("go: -dropretract=%s: %v", arg, err)
	}
	edits = append(edits, func(f *modfile.File) {
		if err := f.DropRetract(vi); err != nil {
			base.Fatalf("go: -dropretract=%s: %v", arg, err)
		}
	})
}

// flagTool implements the -tool flag.
func flagTool(arg string) {
	path := parsePath("tool", arg)
	edits = append(edits, func(f *modfile.File) {
		if err := f.AddTool(path); err != nil {
			base.Fatalf("go: -tool=%s: %v", arg, err)
		}
	})
}

// flagDropTool implements the -droptool flag.
func flagDropTool(arg string) {
	path := parsePath("droptool", arg)
	edits = append(edits, func(f *modfile.File) {
		if err := f.DropTool(path); err != nil {
			base.Fatalf("go: -droptool=%s: %v", arg, err)
		}
	})
}

// fileJSON is the -json output data structure.
type fileJSON struct {
	Module    editModuleJSON
	Go        string `json:",omitempty"`
	Toolchain string `json:",omitempty"`
	Require   []requireJSON
	Exclude   []module.Version
	Replace   []replaceJSON
	Retract   []retractJSON
	Tool      []toolJSON
}

type editModuleJSON struct {
	Path       string
	Deprecated string `json:",omitempty"`
}

type requireJSON struct {
	Path     string
	Version  string `json:",omitempty"`
	Indirect bool   `json:",omitempty"`
}

type replaceJSON struct {
	Old module.Version
	New module.Version
}

type retractJSON struct {
	Low       string `json:",omitempty"`
	High      string `json:",omitempty"`
	Rationale string `json:",omitempty"`
}

type toolJSON struct {
	Path string
}

// editPrintJSON prints the -json output.
func editPrintJSON(modFile *modfile.File) {
	var f fileJSON
	if modFile.Module != nil {
		f.Module = editModuleJSON{
			Path:       modFile.Module.Mod.Path,
			Deprecated: modFile.Module.Deprecated,
		}
	}
	if modFile.Go != nil {
		f.Go = modFile.Go.Version
	}
	if modFile.Toolchain != nil {
		f.Toolchain = modFile.Toolchain.Name
	}
	for _, r := range modFile.Require {
		f.Require = append(f.Require, requireJSON{Path: r.Mod.Path, Version: r.Mod.Version, Indirect: r.Indirect})
	}
	for _, x := range modFile.Exclude {
		f.Exclude = append(f.Exclude, x.Mod)
	}
	for _, r := range modFile.Replace {
		f.Replace = append(f.Replace, replaceJSON{r.Old, r.New})
	}
	for _, r := range modFile.Retract {
		f.Retract = append(f.Retract, retractJSON{r.Low, r.High, r.Rationale})
	}
	for _, t := range modFile.Tool {
		f.Tool = append(f.Tool, toolJSON{t.Path})
	}
	data, err := json.MarshalIndent(&f, "", "\t")
	if err != nil {
		base.Fatalf("go: internal error: %v", err)
	}
	data = append(data, '\n')
	os.Stdout.Write(data)
}
```