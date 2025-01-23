Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Understanding:** The first step is to recognize this is a Go source file (`.go`) and to note the package it belongs to (`modfetch`). The comment at the top gives a general idea: it handles fetching modules. The `codeRepo` struct strongly suggests this is related to code repositories.

2. **Core Functionality Identification (by Struct and Methods):**  The `codeRepo` struct is central. Its fields provide clues about its purpose:
    * `modPath`: The full module path (e.g., `github.com/user/repo/v2`).
    * `code`: An interface (`codehost.Repo`). This immediately signals that this code *doesn't* implement the low-level details of fetching code. It delegates to something else.
    * `codeRoot`:  The root import path in the repository (e.g., `github.com/user/repo`).
    * `codeDir`: The subdirectory within the repo where the module lives.
    * `pathMajor`, `pathPrefix`, `pseudoMajor`: These relate to versioning, especially major version suffixes.

    Next, examine the methods of `codeRepo`:
    * `newCodeRepo`:  A constructor, likely responsible for validating input and setting up the `codeRepo` instance.
    * `ModulePath`:  Simple getter.
    * `CheckReuse`:  Seems to check if a cached repository can be reused.
    * `Versions`:  Fetches available versions of the module. This is a key function.
    * `Stat`: Retrieves information about a specific revision (version/commit).
    * `Latest`:  Gets the latest version.
    * `convert`:  Transforms information from the `codehost.Repo` into a format used by the module system. This hints at abstraction between different repository types.
    * `validatePseudoVersion`: Specifically deals with validating pseudo-versions.
    * `revToRev`, `versionToRev`:  Functions for translating between version strings and repository revision identifiers.
    * `findDir`:  Locates the module directory within the repository. This is important for handling different repository layouts.
    * `GoMod`: Fetches the `go.mod` file. Crucial for Go modules.
    * `LegacyGoMod`: Generates a default `go.mod` if one doesn't exist. Important for older repositories.
    * `retractedVersions`: Handles module retraction.
    * `Zip`:  Downloads and prepares the module as a zip file.

3. **High-Level Functionality Summary:** Based on the struct and methods, we can infer the core purpose:  `codeRepo` acts as an adapter between the Go module system's view of a module and the underlying code repository (handled by the `codehost.Repo` interface). It handles versioning, locating the module within the repo, fetching `go.mod`, and retrieving the module's contents.

4. **Inferring the Go Feature:** The presence of `go.mod`, versioning logic (including major versions and pseudo-versions), and the interaction with a `codehost.Repo` strongly suggest this is part of the **Go Modules** implementation, specifically the part responsible for fetching and managing module source code.

5. **Code Examples:**  To illustrate, think about how these methods would be used. `Versions` would be called to list available versions, so an example using `go list -m -versions` or a direct call to the `modfetch` package would be appropriate. `Stat` would be used to get information about a specific version, useful for `go mod download`. `GoMod` is directly used by `go mod tidy` and similar commands. The `Zip` function is used when downloading module source code. Focus on the typical user interactions with Go modules.

6. **Code Reasoning and Assumptions:**  For the `findDir` function, the logic around `pathMajor` suggests handling modules with major version suffixes. We can make assumptions about repository layouts (module at the root, in a subdirectory, with a major version subdirectory) and show how the function resolves these. The input would be a version, and the output would be the revision, directory, and `go.mod` content.

7. **Command-Line Parameter Handling:** The code itself doesn't directly handle command-line arguments. It's part of the internal implementation. However, we can relate its functionality to `go get`, `go mod download`, `go list`, etc. Explain how these commands would indirectly use the functions in `coderepo.go`.

8. **Common Mistakes:**  Think about common pitfalls users encounter with Go modules. Mismatched module paths, incorrect major version suffixes, and issues with pseudo-versions are common. Create examples that trigger the error conditions in the code (e.g., incorrect `module` directive in `go.mod`).

9. **Review and Refine:** After the initial draft, review the explanation for clarity, accuracy, and completeness. Ensure the examples are correct and easy to understand. Check that all aspects of the prompt are addressed. For instance, explicitly mention the delegation to `codehost.Repo` and the implications of that design.

This structured approach, starting with high-level understanding and gradually diving into specifics, helps in dissecting complex code like this and providing a comprehensive explanation. The key is to connect the code's internal mechanisms to the user-facing features of Go modules.
这段代码是 Go 语言 `cmd/go` 工具中 `modfetch` 包的一部分，主要负责从代码仓库（例如 Git 仓库）中获取 Go 模块的源代码。更具体地说，`codeRepo` 结构体及其相关方法实现了 `modfetch.Repo` 接口，并利用底层的 `codehost.Repo` 接口来完成与具体代码托管服务的交互。

以下是 `go/src/cmd/go/internal/modfetch/coderepo.go` 的主要功能：

1. **模块路径管理:**
   - 它存储了模块的完整路径 (`modPath`)，例如 `github.com/gin-gonic/gin/v2`。
   - 它解析模块路径，区分出路径前缀 (`pathPrefix`) 和主版本后缀 (`pathMajor`)。
   - 它确定模块在代码仓库中的根路径 (`codeRoot`) 和子目录 (`codeDir`)。

2. **版本列表获取:**
   - `Versions(ctx context.Context, prefix string)` 方法用于获取代码仓库中符合指定前缀的版本列表（通常是 Git 标签）。
   - 它会过滤掉不符合语义化版本规范的标签，并根据模块路径的主版本进行过滤。
   - 它能识别并处理带有 `+incompatible` 后缀的版本。

3. **版本信息查询:**
   - `Stat(ctx context.Context, rev string)` 方法用于获取指定版本（可以是版本号、分支名、commit SHA 等）的详细信息，例如 commit SHA、时间戳等。
   - `Latest(ctx context.Context)` 方法用于获取代码仓库的最新版本信息。
   - `convert` 方法将 `codehost.Repo` 返回的版本信息转换为 `modfetch` 包使用的 `RevInfo` 结构体。

4. **伪版本处理:**
   - 它能识别和处理 Go 模块的伪版本（pseudo-version）。
   - `validatePseudoVersion` 方法用于验证伪版本的合法性，包括检查时间戳、commit SHA 和基于的 tag 是否正确。

5. **go.mod 文件处理:**
   - `GoMod(ctx context.Context, version string)` 方法用于获取指定版本的 `go.mod` 文件内容。
   - 如果模块没有 `go.mod` 文件，`LegacyGoMod` 函数会生成一个默认的 `go.mod` 文件。
   - `findDir` 方法用于定位包含 `go.mod` 文件的目录，考虑到模块可能位于仓库的根目录或子目录中，并且可能存在主版本子目录的情况（例如 `v2/go.mod`）。

6. **模块 ZIP 文件获取:**
   - `Zip(ctx context.Context, dst io.Writer, version string)` 方法用于将指定版本的模块内容打包成 ZIP 文件并写入到提供的 `io.Writer`。
   - 它会考虑模块的子目录结构，并提取正确的模块内容。
   - 它还会尝试包含 LICENSE 文件。

7. **模块撤回 (Retraction) 处理:**
   - `retractedVersions` 方法用于解析模块的 `go.mod` 文件中的 `retract` 指令，并返回一个函数，用于判断给定的版本是否已被撤回。

**它是什么 Go 语言功能的实现:**

这段代码是 Go 模块 (Go Modules) 功能的核心组成部分，负责与代码仓库交互，获取模块的元数据和源代码。它是 `go get`, `go mod download`, `go list -m all` 等命令背后的关键机制。

**Go 代码举例说明:**

假设我们有一个代码仓库 `github.com/example/repo`，其中包含一个模块 `github.com/example/repo/mymodule/v2`。

```go
package main

import (
	"context"
	"fmt"
	"os"

	"cmd/go/internal/modfetch"
	"cmd/go/internal/modfetch/codehost"
)

func main() {
	ctx := context.Background()
	modPath := "github.com/example/repo/mymodule/v2"
	codeRoot := "github.com/example/repo"
	repoURL := "https://github.com/example/repo" // 假设仓库是公开的

	// 这里需要一个实际的 codehost.Repo 实现，例如基于 Git 的实现
	// 为了简化示例，我们假设有一个名为 'gitRepo' 的实现了 codehost.Repo 的变量
	// 并且已经初始化好，能够访问 repoURL

	// 假设 gitRepo 是一个已经初始化好的 codehost.Repo
	// 例如： gitRepo := &git.Repo{URL: repoURL}  // 这只是一个概念，实际代码会更复杂

	if gitRepo == nil {
		fmt.Println("需要一个实际的 codehost.Repo 实现")
		return
	}

	repo, err := modfetch.NewCodeRepo(gitRepo, codeRoot, modPath)
	if err != nil {
		fmt.Println("创建 codeRepo 失败:", err)
		return
	}

	// 获取版本列表
	versions, err := repo.Versions(ctx, "")
	if err != nil {
		fmt.Println("获取版本列表失败:", err)
		return
	}
	fmt.Println("可用版本:", versions.List)

	// 获取特定版本的信息
	revInfo, err := repo.Stat(ctx, "v2.0.0")
	if err != nil {
		fmt.Println("获取版本信息失败:", err)
		return
	}
	fmt.Printf("v2.0.0 信息: Commit=%s, Time=%s\n", revInfo.Name, revInfo.Time)

	// 获取 go.mod 文件内容
	gomod, err := repo.GoMod(ctx, "v2.0.0")
	if err != nil {
		fmt.Println("获取 go.mod 失败:", err)
		return
	}
	fmt.Println("go.mod 内容:\n", string(gomod))

	// 将模块打包成 ZIP 文件
	zipFile, err := os.Create("mymodule_v2.0.0.zip")
	if err != nil {
		fmt.Println("创建 ZIP 文件失败:", err)
		return
	}
	defer zipFile.Close()

	err = repo.Zip(ctx, zipFile, "v2.0.0")
	if err != nil {
		fmt.Println("打包 ZIP 文件失败:", err)
		return
	}
	fmt.Println("模块已打包到 mymodule_v2.0.0.zip")
}
```

**假设的输入与输出 (针对 `findDir` 方法):**

假设 `codeRepo` 实例 `r` 对应于模块 `github.com/example/repo/mymodule/v2`，代码仓库的布局如下：

```
repo/
├── go.mod          (内容: module github.com/example/repo)
├── mymodule/
│   └── go.mod      (内容: module github.com/example/repo/mymodule)
│   └── ...
└── mymodule/v2/
    └── go.mod      (内容: module github.com/example/repo/mymodule/v2)
    └── ...
```

**输入:**
- `ctx`: 上下文
- `version`: "v2.0.0"

**输出:**
- `rev`:  假设 "v2.0.0" 标签对应的 commit SHA 为 "abcdef123456"
- `dir`: "mymodule/v2"
- `gomod`: `[]byte`，内容为 `module github.com/example/repo/mymodule/v2\n`
- `err`: `nil`

**代码推理:**

当 `findDir` 被调用时，它会尝试以下步骤：

1. 将版本号 "v2.0.0" 转换为仓库的修订号（可能还是 "v2.0.0"）。
2. 尝试读取 `mymodule/v2/go.mod`。如果存在且内容声明的模块路径与 `modPath` 匹配，则返回对应的目录。
3. 如果 `mymodule/v2/go.mod` 不存在，则尝试读取 `mymodule/go.mod`。如果存在且内容声明的模块路径是 `github.com/example/repo/mymodule`，则不会匹配 `github.com/example/repo/mymodule/v2`，继续下一步。
4. 如果根目录存在 `go.mod`，但其模块路径不是 `github.com/example/repo/mymodule/v2`，则会报错。

在这个例子中，由于存在 `mymodule/v2/go.mod` 且内容匹配，`findDir` 会返回 `mymodule/v2` 作为模块的目录。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是由 `cmd/go` 工具的其他部分调用，那些部分负责解析命令行参数并调用 `modfetch` 包的功能。

例如，当用户执行 `go get github.com/gin-gonic/gin/v2@v2.8.1` 命令时：

1. `cmd/go/internal/get` 包会解析命令行参数，提取模块路径 `github.com/gin-gonic/gin/v2` 和版本 `v2.8.1`。
2. `cmd/go/internal/modload` 包会负责加载模块信息和调用 `modfetch` 包的功能。
3. `modfetch` 包会使用 `codeRepo` 及其依赖的 `codehost.Repo` 实现（例如 `cmd/go/internal/modfetch/git` 中的实现）来与 `github.com` 的 Git 仓库交互。
4. `codeRepo` 的 `Stat` 方法会被调用来获取 `v2.8.1` 的信息。
5. `codeRepo` 的 `GoMod` 方法会被调用来获取 `go.mod` 文件。
6. `codeRepo` 的 `Zip` 方法会被调用来下载模块的源代码。

**使用者易犯错的点:**

- **模块路径与仓库结构的理解偏差:** 用户可能会错误地认为模块路径直接对应于仓库的目录结构。例如，如果一个仓库的根目录下有一个 `go.mod` 文件声明了模块路径为 `github.com/user/repo`，那么该仓库中不能再有子目录包含 `go.mod` 文件声明其他模块，除非使用了主版本后缀 (例如 `v2/go.mod`)。

  **例子:** 假设仓库结构如下：

  ```
  repo/
  ├── go.mod      (module github.com/user/repo)
  └── utils/
      └── go.mod  (module github.com/user/repo/utils)  // 错误！
  ```

  在这种情况下，尝试 `go get github.com/user/repo/utils` 会失败，因为 `github.com/user/repo` 已经是一个模块，不能在其内部再定义新的模块，除非使用主版本路径，如 `utils/v2/go.mod` (模块路径为 `github.com/user/repo/utils/v2`)。

- **对主版本后缀的理解不足:** 用户可能不理解何时以及如何使用主版本后缀（例如 `/v2`）。对于主版本大于 v1 的模块，必须在模块路径中包含主版本后缀，并且仓库的目录结构和 `go.mod` 文件需要相应地组织。

  **例子:** 如果一个库发布了 `v2.0.0` 版本，其模块路径应该是 `github.com/user/repo/v2`。仓库中应该存在一个 `v2/go.mod` 文件，其内容为 `module github.com/user/repo/v2`。如果用户尝试使用 `go get github.com/user/repo@v2.0.0`，将会找不到正确的模块。

- **伪版本的使用场景:** 用户可能不理解伪版本是如何生成的，以及它们在什么情况下会被使用。伪版本用于表示没有对应标签的 commit，其格式包含时间戳和 commit SHA。

总而言之，`go/src/cmd/go/internal/modfetch/coderepo.go` 是 Go 模块功能中一个至关重要的组件，它负责与代码仓库进行交互，获取模块的各种信息和源代码，并为 Go 模块系统的其他部分提供数据支持。理解其功能有助于深入理解 Go 模块的工作原理。

### 提示词
```
这是路径为go/src/cmd/go/internal/modfetch/coderepo.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package modfetch

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cmd/go/internal/gover"
	"cmd/go/internal/modfetch/codehost"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	modzip "golang.org/x/mod/zip"
)

// A codeRepo implements modfetch.Repo using an underlying codehost.Repo.
type codeRepo struct {
	modPath string

	// code is the repository containing this module.
	code codehost.Repo
	// codeRoot is the import path at the root of code.
	codeRoot string
	// codeDir is the directory (relative to root) at which we expect to find the module.
	// If pathMajor is non-empty and codeRoot is not the full modPath,
	// then we look in both codeDir and codeDir/pathMajor[1:].
	codeDir string

	// pathMajor is the suffix of modPath that indicates its major version,
	// or the empty string if modPath is at major version 0 or 1.
	//
	// pathMajor is typically of the form "/vN", but possibly ".vN", or
	// ".vN-unstable" for modules resolved using gopkg.in.
	pathMajor string
	// pathPrefix is the prefix of modPath that excludes pathMajor.
	// It is used only for logging.
	pathPrefix string

	// pseudoMajor is the major version prefix to require when generating
	// pseudo-versions for this module, derived from the module path. pseudoMajor
	// is empty if the module path does not include a version suffix (that is,
	// accepts either v0 or v1).
	pseudoMajor string
}

// newCodeRepo returns a Repo that reads the source code for the module with the
// given path, from the repo stored in code, with the root of the repo
// containing the path given by codeRoot.
func newCodeRepo(code codehost.Repo, codeRoot, path string) (Repo, error) {
	if !hasPathPrefix(path, codeRoot) {
		return nil, fmt.Errorf("mismatched repo: found %s for %s", codeRoot, path)
	}
	pathPrefix, pathMajor, ok := module.SplitPathVersion(path)
	if !ok {
		return nil, fmt.Errorf("invalid module path %q", path)
	}
	if codeRoot == path {
		pathPrefix = path
	}
	pseudoMajor := module.PathMajorPrefix(pathMajor)

	// Compute codeDir = bar, the subdirectory within the repo
	// corresponding to the module root.
	//
	// At this point we might have:
	//	path = github.com/rsc/foo/bar/v2
	//	codeRoot = github.com/rsc/foo
	//	pathPrefix = github.com/rsc/foo/bar
	//	pathMajor = /v2
	//	pseudoMajor = v2
	//
	// which gives
	//	codeDir = bar
	//
	// We know that pathPrefix is a prefix of path, and codeRoot is a prefix of
	// path, but codeRoot may or may not be a prefix of pathPrefix, because
	// codeRoot may be the entire path (in which case codeDir should be empty).
	// That occurs in two situations.
	//
	// One is when a go-import meta tag resolves the complete module path,
	// including the pathMajor suffix:
	//	path = nanomsg.org/go/mangos/v2
	//	codeRoot = nanomsg.org/go/mangos/v2
	//	pathPrefix = nanomsg.org/go/mangos
	//	pathMajor = /v2
	//	pseudoMajor = v2
	//
	// The other is similar: for gopkg.in only, the major version is encoded
	// with a dot rather than a slash, and thus can't be in a subdirectory.
	//	path = gopkg.in/yaml.v2
	//	codeRoot = gopkg.in/yaml.v2
	//	pathPrefix = gopkg.in/yaml
	//	pathMajor = .v2
	//	pseudoMajor = v2
	//
	codeDir := ""
	if codeRoot != path {
		if !hasPathPrefix(pathPrefix, codeRoot) {
			return nil, fmt.Errorf("repository rooted at %s cannot contain module %s", codeRoot, path)
		}
		codeDir = strings.Trim(pathPrefix[len(codeRoot):], "/")
	}

	r := &codeRepo{
		modPath:     path,
		code:        code,
		codeRoot:    codeRoot,
		codeDir:     codeDir,
		pathPrefix:  pathPrefix,
		pathMajor:   pathMajor,
		pseudoMajor: pseudoMajor,
	}

	return r, nil
}

func (r *codeRepo) ModulePath() string {
	return r.modPath
}

func (r *codeRepo) CheckReuse(ctx context.Context, old *codehost.Origin) error {
	return r.code.CheckReuse(ctx, old, r.codeDir)
}

func (r *codeRepo) Versions(ctx context.Context, prefix string) (*Versions, error) {
	// Special case: gopkg.in/macaroon-bakery.v2-unstable
	// does not use the v2 tags (those are for macaroon-bakery.v2).
	// It has no possible tags at all.
	if strings.HasPrefix(r.modPath, "gopkg.in/") && strings.HasSuffix(r.modPath, "-unstable") {
		return &Versions{}, nil
	}

	p := prefix
	if r.codeDir != "" {
		p = r.codeDir + "/" + p
	}
	tags, err := r.code.Tags(ctx, p)
	if err != nil {
		return nil, &module.ModuleError{
			Path: r.modPath,
			Err:  err,
		}
	}
	if tags.Origin != nil {
		tags.Origin.Subdir = r.codeDir
	}

	var list, incompatible []string
	for _, tag := range tags.List {
		if !strings.HasPrefix(tag.Name, p) {
			continue
		}
		v := tag.Name
		if r.codeDir != "" {
			v = v[len(r.codeDir)+1:]
		}
		// Note: ./codehost/codehost.go's isOriginTag knows about these conditions too.
		// If these are relaxed, isOriginTag will need to be relaxed as well.
		if v == "" || v != semver.Canonical(v) {
			// Ignore non-canonical tags: Stat rewrites those to canonical
			// pseudo-versions. Note that we compare against semver.Canonical here
			// instead of module.CanonicalVersion: revToRev strips "+incompatible"
			// suffixes before looking up tags, so a tag like "v2.0.0+incompatible"
			// would not resolve at all. (The Go version string "v2.0.0+incompatible"
			// refers to the "v2.0.0" version tag, which we handle below.)
			continue
		}
		if module.IsPseudoVersion(v) {
			// Ignore tags that look like pseudo-versions: Stat rewrites those
			// unambiguously to the underlying commit, and tagToVersion drops them.
			continue
		}

		if err := module.CheckPathMajor(v, r.pathMajor); err != nil {
			if r.codeDir == "" && r.pathMajor == "" && semver.Major(v) > "v1" {
				incompatible = append(incompatible, v)
			}
			continue
		}

		list = append(list, v)
	}
	semver.Sort(list)
	semver.Sort(incompatible)

	return r.appendIncompatibleVersions(ctx, tags.Origin, list, incompatible)
}

// appendIncompatibleVersions appends "+incompatible" versions to list if
// appropriate, returning the final list.
//
// The incompatible list contains candidate versions without the '+incompatible'
// prefix.
//
// Both list and incompatible must be sorted in semantic order.
func (r *codeRepo) appendIncompatibleVersions(ctx context.Context, origin *codehost.Origin, list, incompatible []string) (*Versions, error) {
	versions := &Versions{
		Origin: origin,
		List:   list,
	}
	if len(incompatible) == 0 || r.pathMajor != "" {
		// No +incompatible versions are possible, so no need to check them.
		return versions, nil
	}

	versionHasGoMod := func(v string) (bool, error) {
		_, err := r.code.ReadFile(ctx, v, "go.mod", codehost.MaxGoMod)
		if err == nil {
			return true, nil
		}
		if !os.IsNotExist(err) {
			return false, &module.ModuleError{
				Path: r.modPath,
				Err:  err,
			}
		}
		return false, nil
	}

	if len(list) > 0 {
		ok, err := versionHasGoMod(list[len(list)-1])
		if err != nil {
			return nil, err
		}
		if ok {
			// The latest compatible version has a go.mod file, so assume that all
			// subsequent versions do as well, and do not include any +incompatible
			// versions. Even if we are wrong, the author clearly intends module
			// consumers to be on the v0/v1 line instead of a higher +incompatible
			// version. (See https://golang.org/issue/34189.)
			//
			// We know of at least two examples where this behavior is desired
			// (github.com/russross/blackfriday@v2.0.0 and
			// github.com/libp2p/go-libp2p@v6.0.23), and (as of 2019-10-29) have no
			// concrete examples for which it is undesired.
			return versions, nil
		}
	}

	var (
		lastMajor         string
		lastMajorHasGoMod bool
	)
	for i, v := range incompatible {
		major := semver.Major(v)

		if major != lastMajor {
			rem := incompatible[i:]
			j := sort.Search(len(rem), func(j int) bool {
				return semver.Major(rem[j]) != major
			})
			latestAtMajor := rem[j-1]

			var err error
			lastMajor = major
			lastMajorHasGoMod, err = versionHasGoMod(latestAtMajor)
			if err != nil {
				return nil, err
			}
		}

		if lastMajorHasGoMod {
			// The latest release of this major version has a go.mod file, so it is
			// not allowed as +incompatible. It would be confusing to include some
			// minor versions of this major version as +incompatible but require
			// semantic import versioning for others, so drop all +incompatible
			// versions for this major version.
			//
			// If we're wrong about a minor version in the middle, users will still be
			// able to 'go get' specific tags for that version explicitly — they just
			// won't appear in 'go list' or as the results for queries with inequality
			// bounds.
			continue
		}
		versions.List = append(versions.List, v+"+incompatible")
	}

	return versions, nil
}

func (r *codeRepo) Stat(ctx context.Context, rev string) (*RevInfo, error) {
	if rev == "latest" {
		return r.Latest(ctx)
	}
	codeRev := r.revToRev(rev)
	info, err := r.code.Stat(ctx, codeRev)
	if err != nil {
		// Note: info may be non-nil to supply Origin for caching error.
		var revInfo *RevInfo
		if info != nil {
			revInfo = &RevInfo{
				Origin:  info.Origin,
				Version: rev,
			}
		}
		return revInfo, &module.ModuleError{
			Path: r.modPath,
			Err: &module.InvalidVersionError{
				Version: rev,
				Err:     err,
			},
		}
	}
	return r.convert(ctx, info, rev)
}

func (r *codeRepo) Latest(ctx context.Context) (*RevInfo, error) {
	info, err := r.code.Latest(ctx)
	if err != nil {
		if info != nil {
			return &RevInfo{Origin: info.Origin}, err
		}
		return nil, err
	}
	return r.convert(ctx, info, "")
}

// convert converts a version as reported by the code host to a version as
// interpreted by the module system.
//
// If statVers is a valid module version, it is used for the Version field.
// Otherwise, the Version is derived from the passed-in info and recent tags.
func (r *codeRepo) convert(ctx context.Context, info *codehost.RevInfo, statVers string) (revInfo *RevInfo, err error) {
	defer func() {
		if info.Origin == nil {
			return
		}
		if revInfo == nil {
			revInfo = new(RevInfo)
		} else if revInfo.Origin != nil {
			panic("internal error: RevInfo Origin unexpectedly already populated")
		}

		origin := *info.Origin
		revInfo.Origin = &origin
		origin.Subdir = r.codeDir

		v := revInfo.Version
		if module.IsPseudoVersion(v) && (v != statVers || !strings.HasPrefix(v, "v0.0.0-")) {
			// Add tags that are relevant to pseudo-version calculation to origin.
			prefix := r.codeDir
			if prefix != "" {
				prefix += "/"
			}
			if r.pathMajor != "" { // "/v2" or "/.v2"
				prefix += r.pathMajor[1:] + "." // += "v2."
			}
			tags, tagsErr := r.code.Tags(ctx, prefix)
			if tagsErr != nil {
				revInfo.Origin = nil
				if err == nil {
					err = tagsErr
				}
			} else {
				origin.TagPrefix = tags.Origin.TagPrefix
				origin.TagSum = tags.Origin.TagSum
			}
		}
	}()

	// If this is a plain tag (no dir/ prefix)
	// and the module path is unversioned,
	// and if the underlying file tree has no go.mod,
	// then allow using the tag with a +incompatible suffix.
	//
	// (If the version is +incompatible, then the go.mod file must not exist:
	// +incompatible is not an ongoing opt-out from semantic import versioning.)
	incompatibleOk := map[string]bool{}
	canUseIncompatible := func(v string) bool {
		if r.codeDir != "" || r.pathMajor != "" {
			// A non-empty codeDir indicates a module within a subdirectory,
			// which necessarily has a go.mod file indicating the module boundary.
			// A non-empty pathMajor indicates a module path with a major-version
			// suffix, which must match.
			return false
		}

		ok, seen := incompatibleOk[""]
		if !seen {
			_, errGoMod := r.code.ReadFile(ctx, info.Name, "go.mod", codehost.MaxGoMod)
			ok = (errGoMod != nil)
			incompatibleOk[""] = ok
		}
		if !ok {
			// A go.mod file exists at the repo root.
			return false
		}

		// Per https://go.dev/issue/51324, previous versions of the 'go' command
		// didn't always check for go.mod files in subdirectories, so if the user
		// requests a +incompatible version explicitly, we should continue to allow
		// it. Otherwise, if vN/go.mod exists, expect that release tags for that
		// major version are intended for the vN module.
		if v != "" && !strings.HasSuffix(statVers, "+incompatible") {
			major := semver.Major(v)
			ok, seen = incompatibleOk[major]
			if !seen {
				_, errGoModSub := r.code.ReadFile(ctx, info.Name, path.Join(major, "go.mod"), codehost.MaxGoMod)
				ok = (errGoModSub != nil)
				incompatibleOk[major] = ok
			}
			if !ok {
				return false
			}
		}

		return true
	}

	// checkCanonical verifies that the canonical version v is compatible with the
	// module path represented by r, adding a "+incompatible" suffix if needed.
	//
	// If statVers is also canonical, checkCanonical also verifies that v is
	// either statVers or statVers with the added "+incompatible" suffix.
	checkCanonical := func(v string) (*RevInfo, error) {
		// If r.codeDir is non-empty, then the go.mod file must exist: the module
		// author — not the module consumer, — gets to decide how to carve up the repo
		// into modules.
		//
		// Conversely, if the go.mod file exists, the module author — not the module
		// consumer — gets to determine the module's path
		//
		// r.findDir verifies both of these conditions. Execute it now so that
		// r.Stat will correctly return a notExistError if the go.mod location or
		// declared module path doesn't match.
		_, _, _, err := r.findDir(ctx, v)
		if err != nil {
			// TODO: It would be nice to return an error like "not a module".
			// Right now we return "missing go.mod", which is a little confusing.
			return nil, &module.ModuleError{
				Path: r.modPath,
				Err: &module.InvalidVersionError{
					Version: v,
					Err:     notExistError{err: err},
				},
			}
		}

		invalidf := func(format string, args ...any) error {
			return &module.ModuleError{
				Path: r.modPath,
				Err: &module.InvalidVersionError{
					Version: v,
					Err:     fmt.Errorf(format, args...),
				},
			}
		}

		// Add the +incompatible suffix if needed or requested explicitly, and
		// verify that its presence or absence is appropriate for this version
		// (which depends on whether it has an explicit go.mod file).

		if v == strings.TrimSuffix(statVers, "+incompatible") {
			v = statVers
		}
		base := strings.TrimSuffix(v, "+incompatible")
		var errIncompatible error
		if !module.MatchPathMajor(base, r.pathMajor) {
			if canUseIncompatible(base) {
				v = base + "+incompatible"
			} else {
				if r.pathMajor != "" {
					errIncompatible = invalidf("module path includes a major version suffix, so major version must match")
				} else {
					errIncompatible = invalidf("module contains a go.mod file, so module path must match major version (%q)", path.Join(r.pathPrefix, semver.Major(v)))
				}
			}
		} else if strings.HasSuffix(v, "+incompatible") {
			errIncompatible = invalidf("+incompatible suffix not allowed: major version %s is compatible", semver.Major(v))
		}

		if statVers != "" && statVers == module.CanonicalVersion(statVers) {
			// Since the caller-requested version is canonical, it would be very
			// confusing to resolve it to anything but itself, possibly with a
			// "+incompatible" suffix. Error out explicitly.
			if statBase := strings.TrimSuffix(statVers, "+incompatible"); statBase != base {
				return nil, &module.ModuleError{
					Path: r.modPath,
					Err: &module.InvalidVersionError{
						Version: statVers,
						Err:     fmt.Errorf("resolves to version %v (%s is not a tag)", v, statBase),
					},
				}
			}
		}

		if errIncompatible != nil {
			return nil, errIncompatible
		}

		return &RevInfo{
			Name:    info.Name,
			Short:   info.Short,
			Time:    info.Time,
			Version: v,
		}, nil
	}

	// Determine version.

	if module.IsPseudoVersion(statVers) {
		// Validate the go.mod location and major version before
		// we check for an ancestor tagged with the pseudo-version base.
		//
		// We can rule out an invalid subdirectory or major version with only
		// shallow commit information, but checking the pseudo-version base may
		// require downloading a (potentially more expensive) full history.
		revInfo, err = checkCanonical(statVers)
		if err != nil {
			return revInfo, err
		}
		if err := r.validatePseudoVersion(ctx, info, statVers); err != nil {
			return nil, err
		}
		return revInfo, nil
	}

	// statVers is not a pseudo-version, so we need to either resolve it to a
	// canonical version or verify that it is already a canonical tag
	// (not a branch).

	// Derive or verify a version from a code repo tag.
	// Tag must have a prefix matching codeDir.
	tagPrefix := ""
	if r.codeDir != "" {
		tagPrefix = r.codeDir + "/"
	}

	isRetracted, err := r.retractedVersions(ctx)
	if err != nil {
		isRetracted = func(string) bool { return false }
	}

	// tagToVersion returns the version obtained by trimming tagPrefix from tag.
	// If the tag is invalid, retracted, or a pseudo-version, tagToVersion returns
	// an empty version.
	tagToVersion := func(tag string) (v string, tagIsCanonical bool) {
		if !strings.HasPrefix(tag, tagPrefix) {
			return "", false
		}
		trimmed := tag[len(tagPrefix):]
		// Tags that look like pseudo-versions would be confusing. Ignore them.
		if module.IsPseudoVersion(tag) {
			return "", false
		}

		v = semver.Canonical(trimmed) // Not module.Canonical: we don't want to pick up an explicit "+incompatible" suffix from the tag.
		if v == "" || !strings.HasPrefix(trimmed, v) {
			return "", false // Invalid or incomplete version (just vX or vX.Y).
		}
		if v == trimmed {
			tagIsCanonical = true
		}
		return v, tagIsCanonical
	}

	// If the VCS gave us a valid version, use that.
	if v, tagIsCanonical := tagToVersion(info.Version); tagIsCanonical {
		if info, err := checkCanonical(v); err == nil {
			return info, err
		}
	}

	// Look through the tags on the revision for either a usable canonical version
	// or an appropriate base for a pseudo-version.
	var (
		highestCanonical string
		pseudoBase       string
	)
	for _, pathTag := range info.Tags {
		v, tagIsCanonical := tagToVersion(pathTag)
		if statVers != "" && semver.Compare(v, statVers) == 0 {
			// The tag is equivalent to the version requested by the user.
			if tagIsCanonical {
				// This tag is the canonical form of the requested version,
				// not some other form with extra build metadata.
				// Use this tag so that the resolved version will match exactly.
				// (If it isn't actually allowed, we'll error out in checkCanonical.)
				return checkCanonical(v)
			} else {
				// The user explicitly requested something equivalent to this tag. We
				// can't use the version from the tag directly: since the tag is not
				// canonical, it could be ambiguous. For example, tags v0.0.1+a and
				// v0.0.1+b might both exist and refer to different revisions.
				//
				// The tag is otherwise valid for the module, so we can at least use it as
				// the base of an unambiguous pseudo-version.
				//
				// If multiple tags match, tagToVersion will canonicalize them to the same
				// base version.
				pseudoBase = v
			}
		}
		// Save the highest non-retracted canonical tag for the revision.
		// If we don't find a better match, we'll use it as the canonical version.
		if tagIsCanonical && semver.Compare(highestCanonical, v) < 0 && !isRetracted(v) {
			if module.MatchPathMajor(v, r.pathMajor) || canUseIncompatible(v) {
				highestCanonical = v
			}
		}
	}

	// If we found a valid canonical tag for the revision, return it.
	// Even if we found a good pseudo-version base, a canonical version is better.
	if highestCanonical != "" {
		return checkCanonical(highestCanonical)
	}

	// Find the highest tagged version in the revision's history, subject to
	// major version and +incompatible constraints. Use that version as the
	// pseudo-version base so that the pseudo-version sorts higher. Ignore
	// retracted versions.
	tagAllowed := func(tag string) bool {
		v, _ := tagToVersion(tag)
		if v == "" {
			return false
		}
		if !module.MatchPathMajor(v, r.pathMajor) && !canUseIncompatible(v) {
			return false
		}
		return !isRetracted(v)
	}
	if pseudoBase == "" {
		tag, err := r.code.RecentTag(ctx, info.Name, tagPrefix, tagAllowed)
		if err != nil && !errors.Is(err, errors.ErrUnsupported) {
			return nil, err
		}
		if tag != "" {
			pseudoBase, _ = tagToVersion(tag)
		}
	}

	return checkCanonical(module.PseudoVersion(r.pseudoMajor, pseudoBase, info.Time, info.Short))
}

// validatePseudoVersion checks that version has a major version compatible with
// r.modPath and encodes a base version and commit metadata that agrees with
// info.
//
// Note that verifying a nontrivial base version in particular may be somewhat
// expensive: in order to do so, r.code.DescendsFrom will need to fetch at least
// enough of the commit history to find a path between version and its base.
// Fortunately, many pseudo-versions — such as those for untagged repositories —
// have trivial bases!
func (r *codeRepo) validatePseudoVersion(ctx context.Context, info *codehost.RevInfo, version string) (err error) {
	defer func() {
		if err != nil {
			if _, ok := err.(*module.ModuleError); !ok {
				if _, ok := err.(*module.InvalidVersionError); !ok {
					err = &module.InvalidVersionError{Version: version, Pseudo: true, Err: err}
				}
				err = &module.ModuleError{Path: r.modPath, Err: err}
			}
		}
	}()

	rev, err := module.PseudoVersionRev(version)
	if err != nil {
		return err
	}
	if rev != info.Short {
		switch {
		case strings.HasPrefix(rev, info.Short):
			return fmt.Errorf("revision is longer than canonical (expected %s)", info.Short)
		case strings.HasPrefix(info.Short, rev):
			return fmt.Errorf("revision is shorter than canonical (expected %s)", info.Short)
		default:
			return fmt.Errorf("does not match short name of revision (expected %s)", info.Short)
		}
	}

	t, err := module.PseudoVersionTime(version)
	if err != nil {
		return err
	}
	if !t.Equal(info.Time.Truncate(time.Second)) {
		return fmt.Errorf("does not match version-control timestamp (expected %s)", info.Time.UTC().Format(module.PseudoVersionTimestampFormat))
	}

	tagPrefix := ""
	if r.codeDir != "" {
		tagPrefix = r.codeDir + "/"
	}

	// A pseudo-version should have a precedence just above its parent revisions,
	// and no higher. Otherwise, it would be possible for library authors to "pin"
	// dependency versions (and bypass the usual minimum version selection) by
	// naming an extremely high pseudo-version rather than an accurate one.
	//
	// Moreover, if we allow a pseudo-version to use any arbitrary pre-release
	// tag, we end up with infinitely many possible names for each commit. Each
	// name consumes resources in the module cache and proxies, so we want to
	// restrict them to a finite set under control of the module author.
	//
	// We address both of these issues by requiring the tag upon which the
	// pseudo-version is based to refer to some ancestor of the revision. We
	// prefer the highest such tag when constructing a new pseudo-version, but do
	// not enforce that property when resolving existing pseudo-versions: we don't
	// know when the parent tags were added, and the highest-tagged parent may not
	// have existed when the pseudo-version was first resolved.
	base, err := module.PseudoVersionBase(strings.TrimSuffix(version, "+incompatible"))
	if err != nil {
		return err
	}
	if base == "" {
		if r.pseudoMajor == "" && semver.Major(version) == "v1" {
			return fmt.Errorf("major version without preceding tag must be v0, not v1")
		}
		return nil
	} else {
		for _, tag := range info.Tags {
			versionOnly := strings.TrimPrefix(tag, tagPrefix)
			if versionOnly == base {
				// The base version is canonical, so if the version from the tag is
				// literally equal (not just equivalent), then the tag is canonical too.
				//
				// We allow pseudo-versions to be derived from non-canonical tags on the
				// same commit, so that tags like "v1.1.0+some-metadata" resolve as
				// close as possible to the canonical version ("v1.1.0") while still
				// enforcing a total ordering ("v1.1.1-0.[…]" with a unique suffix).
				//
				// However, canonical tags already have a total ordering, so there is no
				// reason not to use the canonical tag directly, and we know that the
				// canonical tag must already exist because the pseudo-version is
				// derived from it. In that case, referring to the revision by a
				// pseudo-version derived from its own canonical tag is just confusing.
				return fmt.Errorf("tag (%s) found on revision %s is already canonical, so should not be replaced with a pseudo-version derived from that tag", tag, rev)
			}
		}
	}

	tags, err := r.code.Tags(ctx, tagPrefix+base)
	if err != nil {
		return err
	}

	var lastTag string // Prefer to log some real tag rather than a canonically-equivalent base.
	ancestorFound := false
	for _, tag := range tags.List {
		versionOnly := strings.TrimPrefix(tag.Name, tagPrefix)
		if semver.Compare(versionOnly, base) == 0 {
			lastTag = tag.Name
			ancestorFound, err = r.code.DescendsFrom(ctx, info.Name, tag.Name)
			if ancestorFound {
				break
			}
		}
	}

	if lastTag == "" {
		return fmt.Errorf("preceding tag (%s) not found", base)
	}

	if !ancestorFound {
		if err != nil {
			return err
		}
		rev, err := module.PseudoVersionRev(version)
		if err != nil {
			return fmt.Errorf("not a descendent of preceding tag (%s)", lastTag)
		}
		return fmt.Errorf("revision %s is not a descendent of preceding tag (%s)", rev, lastTag)
	}
	return nil
}

func (r *codeRepo) revToRev(rev string) string {
	if semver.IsValid(rev) {
		if module.IsPseudoVersion(rev) {
			r, _ := module.PseudoVersionRev(rev)
			return r
		}
		if semver.Build(rev) == "+incompatible" {
			rev = rev[:len(rev)-len("+incompatible")]
		}
		if r.codeDir == "" {
			return rev
		}
		return r.codeDir + "/" + rev
	}
	return rev
}

func (r *codeRepo) versionToRev(version string) (rev string, err error) {
	if !semver.IsValid(version) {
		return "", &module.ModuleError{
			Path: r.modPath,
			Err: &module.InvalidVersionError{
				Version: version,
				Err:     errors.New("syntax error"),
			},
		}
	}
	return r.revToRev(version), nil
}

// findDir locates the directory within the repo containing the module.
//
// If r.pathMajor is non-empty, this can be either r.codeDir or — if a go.mod
// file exists — r.codeDir/r.pathMajor[1:].
func (r *codeRepo) findDir(ctx context.Context, version string) (rev, dir string, gomod []byte, err error) {
	rev, err = r.versionToRev(version)
	if err != nil {
		return "", "", nil, err
	}

	// Load info about go.mod but delay consideration
	// (except I/O error) until we rule out v2/go.mod.
	file1 := path.Join(r.codeDir, "go.mod")
	gomod1, err1 := r.code.ReadFile(ctx, rev, file1, codehost.MaxGoMod)
	if err1 != nil && !os.IsNotExist(err1) {
		return "", "", nil, fmt.Errorf("reading %s/%s at revision %s: %v", r.codeRoot, file1, rev, err1)
	}
	mpath1 := modfile.ModulePath(gomod1)
	found1 := err1 == nil && (isMajor(mpath1, r.pathMajor) || r.canReplaceMismatchedVersionDueToBug(mpath1))

	var file2 string
	if r.pathMajor != "" && r.codeRoot != r.modPath && !strings.HasPrefix(r.pathMajor, ".") {
		// Suppose pathMajor is "/v2".
		// Either go.mod should claim v2 and v2/go.mod should not exist,
		// or v2/go.mod should exist and claim v2. Not both.
		// Note that we don't check the full path, just the major suffix,
		// because of replacement modules. This might be a fork of
		// the real module, found at a different path, usable only in
		// a replace directive.
		dir2 := path.Join(r.codeDir, r.pathMajor[1:])
		file2 = path.Join(dir2, "go.mod")
		gomod2, err2 := r.code.ReadFile(ctx, rev, file2, codehost.MaxGoMod)
		if err2 != nil && !os.IsNotExist(err2) {
			return "", "", nil, fmt.Errorf("reading %s/%s at revision %s: %v", r.codeRoot, file2, rev, err2)
		}
		mpath2 := modfile.ModulePath(gomod2)
		found2 := err2 == nil && isMajor(mpath2, r.pathMajor)

		if found1 && found2 {
			return "", "", nil, fmt.Errorf("%s/%s and ...%s/go.mod both have ...%s module paths at revision %s", r.pathPrefix, file1, r.pathMajor, r.pathMajor, rev)
		}
		if found2 {
			return rev, dir2, gomod2, nil
		}
		if err2 == nil {
			if mpath2 == "" {
				return "", "", nil, fmt.Errorf("%s/%s is missing module path at revision %s", r.codeRoot, file2, rev)
			}
			return "", "", nil, fmt.Errorf("%s/%s has non-...%s module path %q at revision %s", r.codeRoot, file2, r.pathMajor, mpath2, rev)
		}
	}

	// Not v2/go.mod, so it's either go.mod or nothing. Which is it?
	if found1 {
		// Explicit go.mod with matching major version ok.
		return rev, r.codeDir, gomod1, nil
	}
	if err1 == nil {
		// Explicit go.mod with non-matching major version disallowed.
		suffix := ""
		if file2 != "" {
			suffix = fmt.Sprintf(" (and ...%s/go.mod does not exist)", r.pathMajor)
		}
		if mpath1 == "" {
			return "", "", nil, fmt.Errorf("%s is missing module path%s at revision %s", file1, suffix, rev)
		}
		if r.pathMajor != "" { // ".v1", ".v2" for gopkg.in
			return "", "", nil, fmt.Errorf("%s has non-...%s module path %q%s at revision %s", file1, r.pathMajor, mpath1, suffix, rev)
		}
		if _, _, ok := module.SplitPathVersion(mpath1); !ok {
			return "", "", nil, fmt.Errorf("%s has malformed module path %q%s at revision %s", file1, mpath1, suffix, rev)
		}
		return "", "", nil, fmt.Errorf("%s has post-%s module path %q%s at revision %s", file1, semver.Major(version), mpath1, suffix, rev)
	}

	if r.codeDir == "" && (r.pathMajor == "" || strings.HasPrefix(r.pathMajor, ".")) {
		// Implicit go.mod at root of repo OK for v0/v1 and for gopkg.in.
		return rev, "", nil, nil
	}

	// Implicit go.mod below root of repo or at v2+ disallowed.
	// Be clear about possibility of using either location for v2+.
	if file2 != "" {
		return "", "", nil, fmt.Errorf("missing %s/go.mod and ...%s/go.mod at revision %s", r.pathPrefix, r.pathMajor, rev)
	}
	return "", "", nil, fmt.Errorf("missing %s/go.mod at revision %s", r.pathPrefix, rev)
}

// isMajor reports whether the versions allowed for mpath are compatible with
// the major version(s) implied by pathMajor, or false if mpath has an invalid
// version suffix.
func isMajor(mpath, pathMajor string) bool {
	if mpath == "" {
		// If we don't have a path, we don't know what version(s) it is compatible with.
		return false
	}
	_, mpathMajor, ok := module.SplitPathVersion(mpath)
	if !ok {
		// An invalid module path is not compatible with any version.
		return false
	}
	if pathMajor == "" {
		// All of the valid versions for a gopkg.in module that requires major
		// version v0 or v1 are compatible with the "v0 or v1" implied by an empty
		// pathMajor.
		switch module.PathMajorPrefix(mpathMajor) {
		case "", "v0", "v1":
			return true
		default:
			return false
		}
	}
	if mpathMajor == "" {
		// Even if pathMajor is ".v0" or ".v1", we can't be sure that a module
		// without a suffix is tagged appropriately. Besides, we don't expect clones
		// of non-gopkg.in modules to have gopkg.in paths, so a non-empty,
		// non-gopkg.in mpath is probably the wrong module for any such pathMajor
		// anyway.
		return false
	}
	// If both pathMajor and mpathMajor are non-empty, then we only care that they
	// have the same major-version validation rules. A clone fetched via a /v2
	// path might replace a module with path gopkg.in/foo.v2-unstable, and that's
	// ok.
	return pathMajor[1:] == mpathMajor[1:]
}

// canReplaceMismatchedVersionDueToBug reports whether versions of r
// could replace versions of mpath with otherwise-mismatched major versions
// due to a historical bug in the Go command (golang.org/issue/34254).
func (r *codeRepo) canReplaceMismatchedVersionDueToBug(mpath string) bool {
	// The bug caused us to erroneously accept unversioned paths as replacements
	// for versioned gopkg.in paths.
	unversioned := r.pathMajor == ""
	replacingGopkgIn := strings.HasPrefix(mpath, "gopkg.in/")
	return unversioned && replacingGopkgIn
}

func (r *codeRepo) GoMod(ctx context.Context, version string) (data []byte, err error) {
	if version != module.CanonicalVersion(version) {
		return nil, fmt.Errorf("version %s is not canonical", version)
	}

	if module.IsPseudoVersion(version) {
		// findDir ignores the metadata encoded in a pseudo-version,
		// only using the revision at the end.
		// Invoke Stat to verify the metadata explicitly so we don't return
		// a bogus file for an invalid version.
		_, err := r.Stat(ctx, version)
		if err != nil {
			return nil, err
		}
	}

	rev, dir, gomod, err := r.findDir(ctx, version)
	if err != nil {
		return nil, err
	}
	if gomod != nil {
		return gomod, nil
	}
	data, err = r.code.ReadFile(ctx, rev, path.Join(dir, "go.mod"), codehost.MaxGoMod)
	if err != nil {
		if os.IsNotExist(err) {
			return LegacyGoMod(r.modPath), nil
		}
		return nil, err
	}
	return data, nil
}

// LegacyGoMod generates a fake go.mod file for a module that doesn't have one.
// The go.mod file contains a module directive and nothing else: no go version,
// no requirements.
//
// We used to try to build a go.mod reflecting pre-existing
// package management metadata files, but the conversion
// was inherently imperfect (because those files don't have
// exactly the same semantics as go.mod) and, when done
// for dependencies in the middle of a build, impossible to
// correct. So we stopped.
func LegacyGoMod(modPath string) []byte {
	return fmt.Appendf(nil, "module %s\n", modfile.AutoQuote(modPath))
}

func (r *codeRepo) modPrefix(rev string) string {
	return r.modPath + "@" + rev
}

func (r *codeRepo) retractedVersions(ctx context.Context) (func(string) bool, error) {
	vs, err := r.Versions(ctx, "")
	if err != nil {
		return nil, err
	}
	versions := vs.List

	for i, v := range versions {
		if strings.HasSuffix(v, "+incompatible") {
			// We're looking for the latest release tag that may list retractions in a
			// go.mod file. +incompatible versions necessarily do not, and they start
			// at major version 2 — which is higher than any version that could
			// validly contain a go.mod file.
			versions = versions[:i]
			break
		}
	}
	if len(versions) == 0 {
		return func(string) bool { return false }, nil
	}

	var highest string
	for i := len(versions) - 1; i >= 0; i-- {
		v := versions[i]
		if semver.Prerelease(v) == "" {
			highest = v
			break
		}
	}
	if highest == "" {
		highest = versions[len(versions)-1]
	}

	data, err := r.GoMod(ctx, highest)
	if err != nil {
		return nil, err
	}
	f, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return nil, err
	}
	retractions := make([]modfile.VersionInterval, 0, len(f.Retract))
	for _, r := range f.Retract {
		retractions = append(retractions, r.VersionInterval)
	}

	return func(v string) bool {
		for _, r := range retractions {
			if semver.Compare(r.Low, v) <= 0 && semver.Compare(v, r.High) <= 0 {
				return true
			}
		}
		return false
	}, nil
}

func (r *codeRepo) Zip(ctx context.Context, dst io.Writer, version string) error {
	if version != module.CanonicalVersion(version) {
		return fmt.Errorf("version %s is not canonical", version)
	}

	if module.IsPseudoVersion(version) {
		// findDir ignores the metadata encoded in a pseudo-version,
		// only using the revision at the end.
		// Invoke Stat to verify the metadata explicitly so we don't return
		// a bogus file for an invalid version.
		_, err := r.Stat(ctx, version)
		if err != nil {
			return err
		}
	}

	rev, subdir, _, err := r.findDir(ctx, version)
	if err != nil {
		return err
	}

	if gomod, err := r.code.ReadFile(ctx, rev, filepath.Join(subdir, "go.mod"), codehost.MaxGoMod); err == nil {
		goVers := gover.GoModLookup(gomod, "go")
		if gover.Compare(goVers, gover.Local()) > 0 {
			return &gover.TooNewError{What: r.ModulePath() + "@" + version, GoVersion: goVers}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	dl, err := r.code.ReadZip(ctx, rev, subdir, codehost.MaxZipFile)
	if err != nil {
		return err
	}
	defer dl.Close()
	subdir = strings.Trim(subdir, "/")

	// Spool to local file.
	f, err := os.CreateTemp("", "go-codehost-")
	if err != nil {
		dl.Close()
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	maxSize := int64(codehost.MaxZipFile)
	lr := &io.LimitedReader{R: dl, N: maxSize + 1}
	if _, err := io.Copy(f, lr); err != nil {
		dl.Close()
		return err
	}
	dl.Close()
	if lr.N <= 0 {
		return fmt.Errorf("downloaded zip file too large")
	}
	size := (maxSize + 1) - lr.N
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}

	// Translate from zip file we have to zip file we want.
	zr, err := zip.NewReader(f, size)
	if err != nil {
		return err
	}

	var files []modzip.File
	if subdir != "" {
		subdir += "/"
	}
	haveLICENSE := false
	topPrefix := ""
	for _, zf := range zr.File {
		if topPrefix == "" {
			i := strings.Index(zf.Name, "/")
			if i < 0 {
				return fmt.Errorf("missing top-level directory prefix")
			}
			topPrefix = zf.Name[:i+1]
		}
		var name string
		var found bool
		if name, found = strings.CutPrefix(zf.Name, topPrefix); !found {
			return fmt.Errorf("zip file contains more than one top-level directory")
		}

		if name, found = strings.CutPrefix(name, subdir); !found {
			continue
		}

		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		files = append(files, zipFile{name: name, f: zf})
		if name == "LICENSE" {
			haveLICENSE = true
		}
	}

	if !haveLICENSE && subdir != "" {
		data, err := r.code.ReadFile(ctx, rev, "LICENSE", codehost.MaxLICENSE)
		if err == nil {
			files = append(files, dataFile{name: "LICENSE", data: data})
		}
	}

	return modzip.Create(dst, module.Version{Path: r.modPath, Version: version}, files)
}

type zipFile struct {
	name string
	f    *zip.File
}

func (f zipFile) Path() string                 { return f.name }
func (f zipFile) Lstat() (fs.FileInfo, error)  { return f.f.FileInfo(), nil }
func (f zipFile) Open() (io.ReadCloser, error) { return f.f.Open() }

type dataFile struct {
	name string
	data []byte
}

func (f dataFile) Path() string                { return f.name }
func (f dataFile) Lstat() (fs.FileInfo, error) { return dataFileInfo{f}, nil }
func (f dataFile) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(f.data)), nil
}

type dataFileInfo struct {
	f dataFile
}

func (fi dataFileInfo) Name() string       { return path.Base(fi.f.name) }
func (fi dataFileInfo) Size() int64        { return int64(len(fi.f.data)) }
func (fi dataFileInfo) Mode() fs.FileMode  { return 0644 }
func (fi dataFileInfo) ModTime() time.Time { return time.Time{} }
func (fi dataFileInfo) IsDir() bool        { return false }
func (fi dataFileInfo) Sys() any           { return nil }

func (fi dataFileInfo) String() string {
	return fs.FormatFileInfo(fi)
}

// hasPathPrefix reports whether the path s begins with the
// elements in prefix.
func hasPathPrefix(s, prefix string) bool {
	switch {
	default:
		return false
	case len(s) == len(prefix):
		return s == prefix
	case len(s) > len(prefix):
		if prefix != "" && prefix[len(prefix)-1] == '/' {
			return strings.HasPrefix(s, prefix)
		}
		return s[len(prefix)] == '/' && s[:len(prefix)] == prefix
	}
}
```