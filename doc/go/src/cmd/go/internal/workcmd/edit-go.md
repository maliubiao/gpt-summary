Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - What's the Goal?**

The first thing I notice is the package name `workcmd` and the command name `edit`. The comments and variable names (like `cmdEdit`, `runEditwork`) strongly suggest this code handles the `go work edit` command. The description, "edit go.work from tools or scripts," gives a high-level purpose.

**2. Core Functionality - Identifying the Verbs**

I scan the `Long` description and the flag definitions. Keywords like "reformats," "adds," "drops," "sets," and "prints" stand out. These are the core actions the `go work edit` command performs. I start mentally listing these functionalities:

* Formatting (`-fmt`)
* Adding/Replacing `godebug` entries (`-godebug`)
* Removing `godebug` entries (`-dropgodebug`)
* Adding `use` directives (`-use`)
* Removing `use` directives (`-dropuse`)
* Adding/Replacing `replace` directives (`-replace`)
* Removing `replace` directives (`-dropreplace`)
* Setting Go version (`-go`)
* Setting toolchain (`-toolchain`)
* Printing the `go.work` content (`-print`, `-json`)

**3. Data Structures - What is being manipulated?**

The comments in the `-json` flag description mention Go types: `GoWork`, `Godebug`, `Use`, and `Replace`. This tells me the underlying structure of the `go.work` file. I look for where these types are referenced or where related data is processed. I see `modfile.WorkFile` being passed around, which is likely the internal representation of the `go.work` file.

**4. Command Line Arguments - How are options passed?**

I examine the `cmdEdit.Flag.XXX` calls in the `init` function. This directly maps the command-line flags to Go variables. I list the flags and their corresponding actions:

* `-fmt`: Boolean, triggers formatting.
* `-go`: String, sets the Go version.
* `-toolchain`: String, sets the toolchain.
* `-json`: Boolean, triggers JSON output.
* `-print`: Boolean, triggers text output.
* `-godebug`:  `flagFunc`, adds/replaces `godebug`.
* `-dropgodebug`: `flagFunc`, removes `godebug`.
* `-use`: `flagFunc`, adds `use`.
* `-dropuse`: `flagFunc`, removes `use`.
* `-replace`: `flagFunc`, adds/replaces `replace`.
* `-dropreplace`: `flagFunc`, removes `replace`.

**5. Control Flow - How does it all work?**

I follow the `runEditwork` function. The key steps are:

* **Argument Parsing:** Handling the `go.work` file path (explicit or implicit).
* **Flag Validation:** Checking for conflicting flags (`-json` and `-print`), valid Go/toolchain versions.
* **Reading the `go.work` file:**  `modload.ReadWorkFile`.
* **Applying Edits:**  Iterating through the `workedits` slice (populated by the flag handlers).
* **Formatting and Cleanup:** `workFile.SortBlocks()`, `workFile.Cleanup()`.
* **Output:** Writing back to the file or printing to stdout (text or JSON).

**6. Deeper Dive into Flag Handlers:**

I look at the `flagEditworkXXX` functions. They parse the flag values and append functions to the `workedits` slice. These functions take a `*modfile.WorkFile` and modify it. This explains how the individual edits are applied. I notice the parsing logic for `-replace` is a bit more complex, handling optional versions.

**7. Example Construction - Putting it Together**

Now, to illustrate the functionality, I think of common use cases and construct examples. For each flag, I create a scenario:

* **Formatting:** `go work edit -fmt`
* **Adding `use`:** `go work edit -use=./module1`
* **Adding `replace`:** `go work edit -replace=old.module=./localmodule`
* **Setting Go version:** `go work edit -go=1.18`

For the `-replace` example, I consider the optional version and create variations. I also consider what the expected output in the `go.work` file would be.

**8. Identifying Potential Mistakes:**

I review the code for areas where users might make errors. The error handling in the flag parsing functions gives clues. For instance:

* Incorrect flag syntax (e.g., missing `=` in `-godebug`).
* Conflicting flags (`-json` and `-print`).
* Invalid Go/toolchain versions.
* Incorrect `-replace` syntax (using `=>` instead of `=`).
* Forgetting that unversioned `new` paths in `-replace` must be local directories.

**9. Refining and Structuring the Output:**

Finally, I organize the information in a clear and structured way, using headings and bullet points. I make sure to address all the prompts in the original request (functionality, code examples, command-line details, potential mistakes). I also try to infer the high-level Go feature (workspaces).

This step-by-step approach allows for a systematic understanding of the code's purpose, functionality, and implementation details, ultimately leading to a comprehensive and informative answer.
这段Go语言代码是 `go work edit` 命令的实现，用于编辑 `go.work` 文件。`go.work` 文件是 Go 1.18 引入的 **工作区 (Workspaces)** 功能的核心组成部分，用于在本地组织多个相关的 Go 模块。

**功能列举:**

`go work edit` 命令提供了一个命令行接口，允许用户通过指定不同的 flag 来修改 `go.work` 文件的内容。主要功能包括：

1. **格式化 `go.work` 文件 (`-fmt`)**: 可以重新格式化 `go.work` 文件，使其具有统一的风格。
2. **添加或替换 `godebug` 指令 (`-godebug=key=value`)**:  向 `go.work` 文件中添加或替换 `godebug` 行，用于设置调试选项。
3. **删除 `godebug` 指令 (`-dropgodebug=key`)**:  从 `go.work` 文件中删除指定的 `godebug` 行。
4. **添加 `use` 指令 (`-use=path`)**:  向 `go.work` 文件中添加一个 `use` 指令，指定一个本地模块的路径。
5. **删除 `use` 指令 (`-dropuse=path`)**:  从 `go.work` 文件中删除指定的 `use` 指令。
6. **添加或替换 `replace` 指令 (`-replace=old[@v]=new[@v]`)**: 向 `go.work` 文件中添加或替换一个 `replace` 指令，用于替换模块依赖。
7. **删除 `replace` 指令 (`-dropreplace=old[@v]`)**: 从 `go.work` 文件中删除指定的 `replace` 指令。
8. **设置 Go 语言版本 (`-go=version`)**: 设置 `go.work` 文件中声明的期望 Go 语言版本。
9. **设置 Go 工具链 (`-toolchain=name`)**: 设置 `go.work` 文件中声明的 Go 工具链。
10. **打印 `go.work` 文件内容到标准输出 (`-print`)**:  将修改后的 `go.work` 文件内容以文本格式打印到终端，而不是写回文件。
11. **打印 `go.work` 文件内容为 JSON 格式 (`-json`)**: 将修改后的 `go.work` 文件内容以 JSON 格式打印到终端，而不是写回文件。

**Go 语言功能实现：工作区 (Workspaces)**

`go work edit` 命令是 Go 语言工作区功能的一部分。工作区允许开发者在本地同时处理多个相互依赖的 Go 模块，而无需将它们发布到版本控制系统。`go.work` 文件定义了工作区的结构，列出了参与工作区的本地模块。

**Go 代码举例说明:**

假设我们有一个名为 `go.work` 的文件，内容如下：

```
go 1.18

use ./moduleA
use ./moduleB
```

现在我们想添加一个 `godebug` 指令，设置 `http2debug=2`，并添加一个使用本地模块 `moduleC` 的指令。我们可以使用 `go work edit` 命令：

```bash
go work edit -godebug=http2debug=2 -use=./moduleC
```

**假设的输入与输出:**

**输入 (执行命令前的 go.work):**

```
go 1.18

use ./moduleA
use ./moduleB
```

**执行的命令:**

```bash
go work edit -godebug=http2debug=2 -use=./moduleC
```

**输出 (执行命令后的 go.work):**

```
go 1.18

godebug http2debug=2

use ./moduleA
use ./moduleB
use ./moduleC
```

**更复杂的例子：添加 replace 指令**

假设我们想将 `example.com/old` 模块替换为本地的 `./local-replace` 目录，可以使用以下命令：

```bash
go work edit -replace=example.com/old=./local-replace
```

**假设的输入与输出:**

**输入 (执行命令前的 go.work):**

```
go 1.18

use ./moduleA
```

**执行的命令:**

```bash
go work edit -replace=example.com/old=./local-replace
```

**输出 (执行命令后的 go.work):**

```
go 1.18

use ./moduleA

replace example.com/old => ./local-replace
```

如果我们要替换特定版本的模块，例如 `example.com/old@v1.0.0`：

```bash
go work edit -replace=example.com/old@v1.0.0=./local-replace
```

**输出 (执行命令后的 go.work):**

```
go 1.18

use ./moduleA

replace example.com/old@v1.0.0 => ./local-replace
```

如果替换为一个指定版本的新模块，例如 `example.com/new@v2.0.0`：

```bash
go work edit -replace=example.com/old@v1.0.0=example.com/new@v2.0.0
```

**输出 (执行命令后的 go.work):**

```
go 1.18

use ./moduleA

replace example.com/old@v1.0.0 => example.com/new@v2.0.0
```

**命令行参数的具体处理:**

`go work edit` 命令的命令行参数主要通过 `flag` 包进行处理。

* **`[go.work]`**:  可选参数，指定要编辑的 `go.work` 文件的路径。如果未指定，命令会在当前目录及其父目录中查找 `go.work` 文件。
* **`-fmt`**: 一个布尔 flag，如果设置，则仅格式化 `go.work` 文件。
* **`-godebug=key=value`**:  使用 `flag.Var` 和自定义的 `flagFunc` 类型来处理，将 `key` 和 `value` 分离并添加到 `workedits` 切片中，后续会对 `modfile.WorkFile` 进行修改。
* **`-dropgodebug=key`**: 类似 `-godebug`，用于删除指定的 `godebug` 行。
* **`-use=path`**:  使用 `flag.Var` 和自定义的 `flagFunc` 处理，将路径添加到 `workedits` 切片中，用于添加 `use` 指令。命令还会尝试读取 `path/go.mod` 文件以获取模块路径。
* **`-dropuse=path`**: 类似 `-use`，用于删除指定的 `use` 指令。
* **`-replace=old[@v]=new[@v]`**: 使用 `flag.Var` 和自定义的 `flagFunc` 处理，解析 `old` 和 `new` 的模块路径和版本信息，并添加到 `workedits` 切片中。解析逻辑比较复杂，需要处理版本号的省略情况。
* **`-dropreplace=old[@v]`**: 类似 `-replace`，用于删除指定的 `replace` 指令。
* **`-go=version`**: 一个字符串 flag，用于设置 Go 语言版本。
* **`-toolchain=name`**: 一个字符串 flag，用于设置 Go 工具链。
* **`-print`**: 一个布尔 flag，如果设置，则将结果打印到标准输出。
* **`-json`**: 一个布尔 flag，如果设置，则将结果以 JSON 格式打印到标准输出。

在 `runEditwork` 函数中，会根据这些 flag 的值，读取 `go.work` 文件，应用相应的修改，然后将结果写回文件或打印到终端。

**使用者易犯错的点:**

1. **`-replace` 语法错误:**
   - 忘记使用 `=` 分隔 `old` 和 `new`。
   - 错误地使用了 `=>` 分隔符，这是 `go.mod` 文件中 `replace` 指令的语法，而不是 `go work edit` 命令的 flag 语法。
   - 当 `new` 是本地路径时，忘记它必须是本地模块根目录的路径。
   - 在需要指定版本时省略 `@v`，或者在不应该指定版本时添加 `@v`。

   **错误示例:**

   ```bash
   go work edit -replace example.com/old => ./local-replace  # 应该使用 =
   go work edit -replace example.com/old=some/file.txt      # 本地路径应该是目录
   ```

2. **同时使用 `-json` 和 `-print`:** 这两个 flag 互斥，不能同时使用。

   **错误示例:**

   ```bash
   go work edit -json -print
   ```

3. **`-godebug` 语法错误:** 忘记使用 `=` 分隔 `key` 和 `value`。

   **错误示例:**

   ```bash
   go work edit -godebug http2debug 2  # 应该使用 =
   ```

4. **操作的 `go.work` 文件不正确:**  如果没有明确指定 `go.work` 文件路径，`go work edit` 会在当前目录及其父目录中查找。如果用户在错误的目录下执行命令，可能会修改错误的 `go.work` 文件。

5. **不理解 `-replace` 中版本号的含义:** 用户可能不清楚何时应该包含版本号，以及省略版本号的含义 (例如，省略 `old` 的版本号会影响所有版本的替换)。

理解这些功能和潜在的错误点可以帮助用户更有效地使用 `go work edit` 命令来管理 Go 工作区。

### 提示词
```
这是路径为go/src/cmd/go/internal/workcmd/edit.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// go work edit

package workcmd

import (
	"cmd/go/internal/base"
	"cmd/go/internal/gover"
	"cmd/go/internal/modload"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/module"

	"golang.org/x/mod/modfile"
)

var cmdEdit = &base.Command{
	UsageLine: "go work edit [editing flags] [go.work]",
	Short:     "edit go.work from tools or scripts",
	Long: `Edit provides a command-line interface for editing go.work,
for use primarily by tools or scripts. It only reads go.work;
it does not look up information about the modules involved.
If no file is specified, Edit looks for a go.work file in the current
directory and its parent directories

The editing flags specify a sequence of editing operations.

The -fmt flag reformats the go.work file without making other changes.
This reformatting is also implied by any other modifications that use or
rewrite the go.mod file. The only time this flag is needed is if no other
flags are specified, as in 'go work edit -fmt'.

The -godebug=key=value flag adds a godebug key=value line,
replacing any existing godebug lines with the given key.

The -dropgodebug=key flag drops any existing godebug lines
with the given key.

The -use=path and -dropuse=path flags
add and drop a use directive from the go.work file's set of module directories.

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

The -use, -dropuse, -replace, and -dropreplace,
editing flags may be repeated, and the changes are applied in the order given.

The -go=version flag sets the expected Go language version.

The -toolchain=name flag sets the Go toolchain to use.

The -print flag prints the final go.work in its text format instead of
writing it back to go.mod.

The -json flag prints the final go.work file in JSON format instead of
writing it back to go.mod. The JSON output corresponds to these Go types:

	type GoWork struct {
		Go        string
		Toolchain string
		Godebug   []Godebug
		Use       []Use
		Replace   []Replace
	}

	type Godebug struct {
		Key   string
		Value string
	}

	type Use struct {
		DiskPath   string
		ModulePath string
	}

	type Replace struct {
		Old Module
		New Module
	}

	type Module struct {
		Path    string
		Version string
	}

See the workspaces reference at https://go.dev/ref/mod#workspaces
for more information.
`,
}

var (
	editFmt       = cmdEdit.Flag.Bool("fmt", false, "")
	editGo        = cmdEdit.Flag.String("go", "", "")
	editToolchain = cmdEdit.Flag.String("toolchain", "", "")
	editJSON      = cmdEdit.Flag.Bool("json", false, "")
	editPrint     = cmdEdit.Flag.Bool("print", false, "")
	workedits     []func(file *modfile.WorkFile) // edits specified in flags
)

type flagFunc func(string)

func (f flagFunc) String() string     { return "" }
func (f flagFunc) Set(s string) error { f(s); return nil }

func init() {
	cmdEdit.Run = runEditwork // break init cycle

	cmdEdit.Flag.Var(flagFunc(flagEditworkGodebug), "godebug", "")
	cmdEdit.Flag.Var(flagFunc(flagEditworkDropGodebug), "dropgodebug", "")
	cmdEdit.Flag.Var(flagFunc(flagEditworkUse), "use", "")
	cmdEdit.Flag.Var(flagFunc(flagEditworkDropUse), "dropuse", "")
	cmdEdit.Flag.Var(flagFunc(flagEditworkReplace), "replace", "")
	cmdEdit.Flag.Var(flagFunc(flagEditworkDropReplace), "dropreplace", "")
	base.AddChdirFlag(&cmdEdit.Flag)
}

func runEditwork(ctx context.Context, cmd *base.Command, args []string) {
	if *editJSON && *editPrint {
		base.Fatalf("go: cannot use both -json and -print")
	}

	if len(args) > 1 {
		base.Fatalf("go: 'go help work edit' accepts at most one argument")
	}
	var gowork string
	if len(args) == 1 {
		gowork = args[0]
	} else {
		modload.InitWorkfile()
		gowork = modload.WorkFilePath()
	}
	if gowork == "" {
		base.Fatalf("go: no go.work file found\n\t(run 'go work init' first or specify path using GOWORK environment variable)")
	}

	if *editGo != "" && *editGo != "none" {
		if !modfile.GoVersionRE.MatchString(*editGo) {
			base.Fatalf(`go work: invalid -go option; expecting something like "-go %s"`, gover.Local())
		}
	}
	if *editToolchain != "" && *editToolchain != "none" {
		if !modfile.ToolchainRE.MatchString(*editToolchain) {
			base.Fatalf(`go work: invalid -toolchain option; expecting something like "-toolchain go%s"`, gover.Local())
		}
	}

	anyFlags := *editGo != "" ||
		*editToolchain != "" ||
		*editJSON ||
		*editPrint ||
		*editFmt ||
		len(workedits) > 0

	if !anyFlags {
		base.Fatalf("go: no flags specified (see 'go help work edit').")
	}

	workFile, err := modload.ReadWorkFile(gowork)
	if err != nil {
		base.Fatalf("go: errors parsing %s:\n%s", base.ShortPath(gowork), err)
	}

	if *editGo == "none" {
		workFile.DropGoStmt()
	} else if *editGo != "" {
		if err := workFile.AddGoStmt(*editGo); err != nil {
			base.Fatalf("go: internal error: %v", err)
		}
	}
	if *editToolchain == "none" {
		workFile.DropToolchainStmt()
	} else if *editToolchain != "" {
		if err := workFile.AddToolchainStmt(*editToolchain); err != nil {
			base.Fatalf("go: internal error: %v", err)
		}
	}

	if len(workedits) > 0 {
		for _, edit := range workedits {
			edit(workFile)
		}
	}

	workFile.SortBlocks()
	workFile.Cleanup() // clean file after edits

	// Note: No call to modload.UpdateWorkFile here.
	// Edit's job is only to make the edits on the command line,
	// not to apply the kinds of semantic changes that
	// UpdateWorkFile does (or would eventually do, if we
	// decide to add the module comments in go.work).

	if *editJSON {
		editPrintJSON(workFile)
		return
	}

	if *editPrint {
		os.Stdout.Write(modfile.Format(workFile.Syntax))
		return
	}

	modload.WriteWorkFile(gowork, workFile)
}

// flagEditworkGodebug implements the -godebug flag.
func flagEditworkGodebug(arg string) {
	key, value, ok := strings.Cut(arg, "=")
	if !ok || strings.ContainsAny(arg, "\"`',") {
		base.Fatalf("go: -godebug=%s: need key=value", arg)
	}
	workedits = append(workedits, func(f *modfile.WorkFile) {
		if err := f.AddGodebug(key, value); err != nil {
			base.Fatalf("go: -godebug=%s: %v", arg, err)
		}
	})
}

// flagEditworkDropGodebug implements the -dropgodebug flag.
func flagEditworkDropGodebug(arg string) {
	workedits = append(workedits, func(f *modfile.WorkFile) {
		if err := f.DropGodebug(arg); err != nil {
			base.Fatalf("go: -dropgodebug=%s: %v", arg, err)
		}
	})
}

// flagEditworkUse implements the -use flag.
func flagEditworkUse(arg string) {
	workedits = append(workedits, func(f *modfile.WorkFile) {
		_, mf, err := modload.ReadModFile(filepath.Join(arg, "go.mod"), nil)
		modulePath := ""
		if err == nil {
			modulePath = mf.Module.Mod.Path
		}
		f.AddUse(modload.ToDirectoryPath(arg), modulePath)
		if err := f.AddUse(modload.ToDirectoryPath(arg), ""); err != nil {
			base.Fatalf("go: -use=%s: %v", arg, err)
		}
	})
}

// flagEditworkDropUse implements the -dropuse flag.
func flagEditworkDropUse(arg string) {
	workedits = append(workedits, func(f *modfile.WorkFile) {
		if err := f.DropUse(modload.ToDirectoryPath(arg)); err != nil {
			base.Fatalf("go: -dropdirectory=%s: %v", arg, err)
		}
	})
}

// allowedVersionArg returns whether a token may be used as a version in go.mod.
// We don't call modfile.CheckPathVersion, because that insists on versions
// being in semver form, but here we want to allow versions like "master" or
// "1234abcdef", which the go command will resolve the next time it runs (or
// during -fix).  Even so, we need to make sure the version is a valid token.
func allowedVersionArg(arg string) bool {
	return !modfile.MustQuote(arg)
}

// parsePathVersionOptional parses path[@version], using adj to
// describe any errors.
func parsePathVersionOptional(adj, arg string, allowDirPath bool) (path, version string, err error) {
	before, after, found := strings.Cut(arg, "@")
	if !found {
		path = arg
	} else {
		path, version = strings.TrimSpace(before), strings.TrimSpace(after)
	}
	if err := module.CheckImportPath(path); err != nil {
		if !allowDirPath || !modfile.IsDirectoryPath(path) {
			return path, version, fmt.Errorf("invalid %s path: %v", adj, err)
		}
	}
	if path != arg && !allowedVersionArg(version) {
		return path, version, fmt.Errorf("invalid %s version: %q", adj, version)
	}
	return path, version, nil
}

// flagEditworkReplace implements the -replace flag.
func flagEditworkReplace(arg string) {
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

	workedits = append(workedits, func(f *modfile.WorkFile) {
		if err := f.AddReplace(oldPath, oldVersion, newPath, newVersion); err != nil {
			base.Fatalf("go: -replace=%s: %v", arg, err)
		}
	})
}

// flagEditworkDropReplace implements the -dropreplace flag.
func flagEditworkDropReplace(arg string) {
	path, version, err := parsePathVersionOptional("old", arg, true)
	if err != nil {
		base.Fatalf("go: -dropreplace=%s: %v", arg, err)
	}
	workedits = append(workedits, func(f *modfile.WorkFile) {
		if err := f.DropReplace(path, version); err != nil {
			base.Fatalf("go: -dropreplace=%s: %v", arg, err)
		}
	})
}

type replaceJSON struct {
	Old module.Version
	New module.Version
}

// editPrintJSON prints the -json output.
func editPrintJSON(workFile *modfile.WorkFile) {
	var f workfileJSON
	if workFile.Go != nil {
		f.Go = workFile.Go.Version
	}
	for _, d := range workFile.Use {
		f.Use = append(f.Use, useJSON{DiskPath: d.Path, ModPath: d.ModulePath})
	}

	for _, r := range workFile.Replace {
		f.Replace = append(f.Replace, replaceJSON{r.Old, r.New})
	}
	data, err := json.MarshalIndent(&f, "", "\t")
	if err != nil {
		base.Fatalf("go: internal error: %v", err)
	}
	data = append(data, '\n')
	os.Stdout.Write(data)
}

// workfileJSON is the -json output data structure.
type workfileJSON struct {
	Go      string `json:",omitempty"`
	Use     []useJSON
	Replace []replaceJSON
}

type useJSON struct {
	DiskPath string
	ModPath  string `json:",omitempty"`
}
```