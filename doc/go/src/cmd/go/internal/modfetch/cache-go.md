Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the code, an example of its usage, explanation of any CLI parameters, and common mistakes. The core focus is on `go/src/cmd/go/internal/modfetch/cache.go`, suggesting it's related to caching module downloads.

2. **Initial Scan for Key Concepts:** Quickly read through the code, looking for prominent keywords and function names. Terms like `cacheDir`, `CachePath`, `DownloadDir`, `lockVersion`, `SideLock`, `cachingRepo`, `readDiskStat`, `writeDiskGoMod`, `GOMODCACHE`, and `GOPROXY` jump out. These strongly indicate the code is about managing a local cache for Go modules.

3. **Function-by-Function Analysis:** Go through each function, determining its purpose:
    * `cacheDir`:  Calculates the directory for a module's cache. It uses `module.EscapePath` which suggests encoding to avoid invalid characters. It relies on `cfg.GOMODCACHE`.
    * `CachePath`: Constructs the full path to a cached file (info, mod, zip, etc.) for a specific module version. Uses `module.EscapeVersion`. Handles `ErrToolchain`.
    * `DownloadDir`:  Determines the download directory for a module. Crucially, it also *checks* for the presence of certain files (`.partial`, `.ziphash`) to ensure the download is complete. Introduces `DownloadDirPartialError`.
    * `lockVersion`: Creates a lock file to prevent concurrent downloads/extractions of the same module version. Uses `lockedfile`.
    * `SideLock`:  Creates a global lock for operations that might modify files outside the module cache (like `go.sum`).
    * `cachingRepo`: Implements a caching layer *around* another `Repo` interface. This is a common optimization pattern. It uses `par.ErrCache` for thread-safe caching of various data (versions, stats, go.mod).
    * `newCachingRepo`: Constructor for `cachingRepo`.
    * Methods of `cachingRepo` (`repo`, `CheckReuse`, `ModulePath`, `Versions`, `Stat`, `Latest`, `GoMod`, `Zip`): These delegate to the underlying `Repo` but with caching logic. Notice the use of `readDisk...` and `writeDisk...` functions.
    * `InfoFile`:  Retrieves module info, checking the disk cache first and then potentially hitting proxies.
    * `GoMod`:  Retrieves the `go.mod` content, similarly checking the cache.
    * `GoModFile`: Returns the path to the cached `go.mod` file.
    * `GoModSum`: Calculates the checksum of the `go.mod` file.
    * `readDiskStat`, `readDiskGoMod`, `readDiskCache`: Read cached data from disk. `readDiskStat` has logic for handling commit hashes.
    * `readDiskStatByHash`:  Specific logic for finding cached info by commit hash.
    * `writeDiskStat`, `writeDiskGoMod`, `writeDiskCache`: Write data to the cache. Uses temporary files for atomicity.
    * `tempFile`: Helper function for creating temporary files.
    * `rewriteVersionList`: Updates the "list" file in the module's `@v` directory, containing available versions.
    * `checkCacheDir`: Ensures the `GOMODCACHE` directory exists and is valid.

4. **Inferring the Go Feature:** Based on the function names and operations, it's clear this code is a core part of the Go module system's caching mechanism. It's responsible for:
    * **Storing downloaded module data:**  Source code (zip), `go.mod` files, and metadata (`.info`, `.ziphash`).
    * **Organizing the cache:** Using a specific directory structure under `GOMODCACHE`.
    * **Retrieving cached data:**  Avoiding redundant downloads.
    * **Locking mechanisms:** Ensuring data consistency during concurrent operations.
    * **Interacting with module proxies:**  Fetching data when not in the cache.

5. **Code Example Construction:** Create a simple example demonstrating a common use case: retrieving information about a module. Choose functions like `InfoFile` or `GoMod` that clearly interact with the caching mechanism. Provide plausible input and expected output based on the function's logic.

6. **Command-Line Parameters:**  Focus on the environment variables mentioned in the code (`GOMODCACHE`, `GOPROXY`). Explain their purpose and how they influence the caching behavior.

7. **Common Mistakes:** Think about potential pitfalls for users. Incorrect `GOMODCACHE` settings are a primary concern. Explain the consequences of a relative path.

8. **Refine and Organize:** Structure the answer logically, starting with the high-level functionality, then the code example, followed by CLI parameters and common mistakes. Ensure clear explanations and formatting. Use code blocks for Go code and backticks for file paths and variable names.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Might have focused too much on individual low-level file operations. Realized the need to abstract up to the higher-level functionality of module caching.
* **Code Example Clarity:**  Ensured the example is concise and demonstrates the interaction with the cache, rather than being overly complex.
* **Parameter Detail:** Provided specific examples for `GOPROXY` values to illustrate their impact.
* **Mistake Emphasis:**  Highlighted the "relative path" error for `GOMODCACHE` as a key user mistake.
* **Terminology Consistency:** Used consistent terms like "module path," "module version," etc.

By following these steps, the comprehensive and accurate answer provided earlier can be constructed. The process involves understanding the code's purpose, analyzing its components, inferring its role within the broader system, and then illustrating its usage and potential pitfalls.
这段代码是 Go 语言 `go` 命令内部 `modfetch` 包的一部分，主要负责 **管理和操作 Go 模块的本地缓存**。

以下是它的主要功能：

**1. 定义和管理缓存目录结构:**

* **`cacheDir(ctx context.Context, path string)`:**  根据给定的模块路径 (`path`)，计算出该模块在本地缓存中的根目录。这个根目录位于 `$GOMODCACHE/cache/download/<escaped_path>/@v`。
* **`CachePath(ctx context.Context, m module.Version, suffix string)`:**  构建模块特定文件（例如 `.info`, `.mod`, `.zip`）在缓存中的完整路径。它依赖于 `cacheDir`，并根据模块的版本 (`m.Version`) 和文件后缀 (`suffix`) 生成文件名。
* **`DownloadDir(ctx context.Context, m module.Version)`:**  确定模块下载后应该存放的目录。它会检查目录是否存在，以及一些标志文件（`.partial`, `.ziphash`）来判断下载是否完整。如果目录存在但不完整，会返回一个 `DownloadDirPartialError` 类型的错误。

**2. 提供文件锁机制:**

* **`lockVersion(ctx context.Context, mod module.Version)`:**  为特定的模块版本创建一个锁文件，防止并发地下载和解压同一个模块版本。
* **`SideLock(ctx context.Context)`:**  创建一个全局锁，用于保护对模块缓存外部文件的修改，例如 `go.sum` 或项目中的 `go.mod` 文件。

**3. 实现缓存仓库 (`cachingRepo`):**

* **`cachingRepo` 结构体** 封装了一个底层的 `Repo` 接口，并为其提供缓存功能，避免重复的网络请求。它缓存了模块的版本列表、修订信息（`RevInfo`）、最新的修订信息以及 `go.mod` 文件内容。
* **`newCachingRepo(ctx context.Context, path string, initRepo func(context.Context) (Repo, error))`:**  创建一个新的 `cachingRepo` 实例。`initRepo` 是一个函数，用于在首次访问时初始化底层的 `Repo`。
* **`cachingRepo` 的方法 (`Versions`, `Stat`, `Latest`, `GoMod`, `Zip` 等):** 这些方法先尝试从缓存中读取数据，如果缓存中不存在，则调用底层 `Repo` 的方法获取数据，并将结果写入缓存。

**4. 读取和写入缓存数据:**

* **`readDiskStat(ctx context.Context, path, rev string)`:**  从磁盘读取指定模块和修订版本的缓存 `info` 文件。如果找不到，会尝试根据 commit hash 查找伪版本。
* **`readDiskGoMod(ctx context.Context, path, rev string)`:**  从磁盘读取指定模块和修订版本的缓存 `go.mod` 文件。
* **`readDiskCache(ctx context.Context, path, rev, suffix string)`:**  一个通用的函数，用于从磁盘读取指定模块、修订版本和后缀的缓存文件。
* **`writeDiskStat(ctx context.Context, file string, info *RevInfo)`:**  将 `RevInfo` 数据写入缓存文件。
* **`writeDiskGoMod(ctx context.Context, file string, text []byte)`:**  将 `go.mod` 文件内容写入缓存文件。
* **`writeDiskCache(ctx context.Context, file string, data []byte)`:**  一个通用的函数，用于将数据写入缓存文件。它使用临时文件和原子重命名来保证数据一致性。

**5. 其他辅助功能:**

* **`InfoFile(ctx context.Context, path, version string)`:**  获取指定模块和版本的 `RevInfo`，优先从缓存读取。
* **`GoMod(ctx context.Context, path, rev string)`:**  获取指定模块和修订版本的 `go.mod` 内容，优先从缓存读取。
* **`GoModFile(ctx context.Context, path, version string)`:**  获取指定模块和版本的缓存 `go.mod` 文件的路径。
* **`GoModSum(ctx context.Context, path, version string)`:**  计算指定模块版本 `go.mod` 文件的校验和。
* **`rewriteVersionList(ctx context.Context, dir string)`:**  在写入新的 `.mod` 文件后，更新模块 `@v` 目录下的 `list` 文件，该文件包含了该模块的所有可用版本。
* **`checkCacheDir(ctx context.Context)`:**  检查 `$GOMODCACHE` 目录是否存在且有效。

**它是什么 Go 语言功能的实现:**

这段代码是 **Go 模块（Go Modules）系统**中用于管理本地模块缓存的核心部分。 当你使用 `go get`, `go build` 等命令下载或使用模块时，`go` 命令会利用这些函数将下载的模块数据（源代码、`go.mod` 等）存储在本地缓存中，并在后续使用时优先从缓存中读取，从而提高构建速度并减少网络请求。

**Go 代码示例:**

假设我们要获取 `golang.org/x/text` 模块 `v0.3.7` 版本的 `go.mod` 文件内容：

```go
package main

import (
	"context"
	"fmt"
	"log"

	"cmd/go/internal/cfg"
	"cmd/go/internal/modfetch"
	"golang.org/x/mod/module"
)

func main() {
	ctx := context.Background()

	// 模拟 go 命令的配置，需要设置 GOMODCACHE
	cfg.GOMODCACHE = "/path/to/your/go/pkg/mod" // 替换为你实际的 GOMODCACHE 路径

	mod := module.Version{Path: "golang.org/x/text", Version: "v0.3.7"}

	// 获取缓存的 go.mod 文件路径
	modFile, err := modfetch.CachePath(ctx, mod, "mod")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Cached go.mod file path:", modFile)

	// 获取 go.mod 文件内容
	content, err := modfetch.GoMod(ctx, mod.Path, mod.Version)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\nContent of go.mod:\n", string(content))
}
```

**假设的输入与输出:**

* **假设的输入:**
    * `cfg.GOMODCACHE` 被设置为 `/Users/youruser/go/pkg/mod` (或者你的系统上的实际路径)。
    * 本地缓存中已经存在 `golang.org/x/text@v0.3.7` 的相关文件。

* **假设的输出:**

```
Cached go.mod file path: /Users/youruser/go/pkg/mod/cache/download/golang.org/x/text/@v/v0.3.7.mod

Content of go.mod:
module golang.org/x/text

go 1.12

require golang.org/x/net v0.0.0-20190620200745-ca631d804671 // indirect
```

如果缓存中不存在该模块版本，`modfetch.GoMod` 函数会触发 `go` 命令去下载该模块并将其缓存。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是在 `go` 命令内部被调用的，而 `go` 命令的参数解析发生在更上层的代码中。

然而，这段代码间接地受到了以下环境变量的影响：

* **`GOMODCACHE`:**  这个环境变量指定了 Go 模块缓存的路径。`checkCacheDir` 函数会检查这个目录是否存在和有效。这段代码中的所有缓存路径计算都基于 `cfg.GOMODCACHE` 的值。如果 `GOMODCACHE` 没有设置，`go` 命令会默认使用 `$GOPATH/pkg/mod`。
* **`GOPROXY`:** 虽然这段代码没有直接处理 `GOPROXY`，但 `TryProxies` 函数（未在此代码片段中完全展示）会使用 `GOPROXY` 环境变量来决定从哪些代理服务器下载模块。如果本地缓存中找不到模块，`go` 命令会根据 `GOPROXY` 的配置去尝试从不同的代理下载。
* **`GONOSUMDB` 和 `GOPRIVATE`:**  这些环境变量会影响模块的校验和验证和私有模块的下载，间接地影响缓存的行为。例如，被 `GONOSUMDB` 或 `GOPRIVATE` 排除的模块可能不会被缓存或以不同的方式处理。

**使用者易犯错的点:**

使用者通常不需要直接与这段代码交互。但以下是一些与 Go 模块缓存相关的常见错误，可能与这段代码的功能有关：

* **手动修改 `$GOMODCACHE` 中的文件:**  直接修改缓存目录中的文件可能会导致数据不一致或校验失败。`go` 命令依赖于缓存文件的完整性和正确性。
* **删除 `$GOMODCACHE` 目录的一部分:**  不完整地删除缓存目录可能导致 `go` 命令出现错误，因为它可能找不到期望的文件或发现缓存损坏。应该使用 `go clean -modcache` 命令来清理模块缓存。
* **`GOMODCACHE` 设置为相对路径:** `checkCacheDir` 函数会检查 `GOMODCACHE` 是否为绝对路径。如果设置为相对路径，会导致错误。

**示例说明 `GOMODCACHE` 设置为相对路径的错误:**

假设用户错误地将 `GOMODCACHE` 设置为当前工作目录下的一个名为 `gomodcache` 的文件夹：

```bash
export GOMODCACHE=gomodcache
go build
```

这将导致 `checkCacheDir` 函数返回错误，因为 `gomodcache` 是一个相对路径。错误信息可能类似于：

```
go: GOMODCACHE entry is relative; must be absolute path: "gomodcache".
```

总而言之，这段代码是 Go 模块缓存的核心实现，负责管理模块在本地的存储、读取和锁定，以提高构建效率和保证模块依赖的一致性。用户通常不需要直接操作这些代码，但理解其功能有助于理解 Go 模块的工作原理和避免一些常见错误。

### 提示词
```
这是路径为go/src/cmd/go/internal/modfetch/cache.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"cmd/go/internal/base"
	"cmd/go/internal/cfg"
	"cmd/go/internal/gover"
	"cmd/go/internal/lockedfile"
	"cmd/go/internal/modfetch/codehost"
	"cmd/internal/par"
	"cmd/internal/robustio"
	"cmd/internal/telemetry/counter"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

func cacheDir(ctx context.Context, path string) (string, error) {
	if err := checkCacheDir(ctx); err != nil {
		return "", err
	}
	enc, err := module.EscapePath(path)
	if err != nil {
		return "", err
	}
	return filepath.Join(cfg.GOMODCACHE, "cache/download", enc, "/@v"), nil
}

func CachePath(ctx context.Context, m module.Version, suffix string) (string, error) {
	if gover.IsToolchain(m.Path) {
		return "", ErrToolchain
	}
	dir, err := cacheDir(ctx, m.Path)
	if err != nil {
		return "", err
	}
	if !gover.ModIsValid(m.Path, m.Version) {
		return "", fmt.Errorf("non-semver module version %q", m.Version)
	}
	if module.CanonicalVersion(m.Version) != m.Version {
		return "", fmt.Errorf("non-canonical module version %q", m.Version)
	}
	encVer, err := module.EscapeVersion(m.Version)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, encVer+"."+suffix), nil
}

// DownloadDir returns the directory to which m should have been downloaded.
// An error will be returned if the module path or version cannot be escaped.
// An error satisfying errors.Is(err, fs.ErrNotExist) will be returned
// along with the directory if the directory does not exist or if the directory
// is not completely populated.
func DownloadDir(ctx context.Context, m module.Version) (string, error) {
	if gover.IsToolchain(m.Path) {
		return "", ErrToolchain
	}
	if err := checkCacheDir(ctx); err != nil {
		return "", err
	}
	enc, err := module.EscapePath(m.Path)
	if err != nil {
		return "", err
	}
	if !gover.ModIsValid(m.Path, m.Version) {
		return "", fmt.Errorf("non-semver module version %q", m.Version)
	}
	if module.CanonicalVersion(m.Version) != m.Version {
		return "", fmt.Errorf("non-canonical module version %q", m.Version)
	}
	encVer, err := module.EscapeVersion(m.Version)
	if err != nil {
		return "", err
	}

	// Check whether the directory itself exists.
	dir := filepath.Join(cfg.GOMODCACHE, enc+"@"+encVer)
	if fi, err := os.Stat(dir); os.IsNotExist(err) {
		return dir, err
	} else if err != nil {
		return dir, &DownloadDirPartialError{dir, err}
	} else if !fi.IsDir() {
		return dir, &DownloadDirPartialError{dir, errors.New("not a directory")}
	}

	// Check if a .partial file exists. This is created at the beginning of
	// a download and removed after the zip is extracted.
	partialPath, err := CachePath(ctx, m, "partial")
	if err != nil {
		return dir, err
	}
	if _, err := os.Stat(partialPath); err == nil {
		return dir, &DownloadDirPartialError{dir, errors.New("not completely extracted")}
	} else if !os.IsNotExist(err) {
		return dir, err
	}

	// Check if a .ziphash file exists. It should be created before the
	// zip is extracted, but if it was deleted (by another program?), we need
	// to re-calculate it. Note that checkMod will repopulate the ziphash
	// file if it doesn't exist, but if the module is excluded by checks
	// through GONOSUMDB or GOPRIVATE, that check and repopulation won't happen.
	ziphashPath, err := CachePath(ctx, m, "ziphash")
	if err != nil {
		return dir, err
	}
	if _, err := os.Stat(ziphashPath); os.IsNotExist(err) {
		return dir, &DownloadDirPartialError{dir, errors.New("ziphash file is missing")}
	} else if err != nil {
		return dir, err
	}
	return dir, nil
}

// DownloadDirPartialError is returned by DownloadDir if a module directory
// exists but was not completely populated.
//
// DownloadDirPartialError is equivalent to fs.ErrNotExist.
type DownloadDirPartialError struct {
	Dir string
	Err error
}

func (e *DownloadDirPartialError) Error() string     { return fmt.Sprintf("%s: %v", e.Dir, e.Err) }
func (e *DownloadDirPartialError) Is(err error) bool { return err == fs.ErrNotExist }

// lockVersion locks a file within the module cache that guards the downloading
// and extraction of the zipfile for the given module version.
func lockVersion(ctx context.Context, mod module.Version) (unlock func(), err error) {
	path, err := CachePath(ctx, mod, "lock")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
		return nil, err
	}
	return lockedfile.MutexAt(path).Lock()
}

// SideLock locks a file within the module cache that previously guarded
// edits to files outside the cache, such as go.sum and go.mod files in the
// user's working directory.
// If err is nil, the caller MUST eventually call the unlock function.
func SideLock(ctx context.Context) (unlock func(), err error) {
	if err := checkCacheDir(ctx); err != nil {
		return nil, err
	}

	path := filepath.Join(cfg.GOMODCACHE, "cache", "lock")
	if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return lockedfile.MutexAt(path).Lock()
}

// A cachingRepo is a cache around an underlying Repo,
// avoiding redundant calls to ModulePath, Versions, Stat, Latest, and GoMod (but not CheckReuse or Zip).
// It is also safe for simultaneous use by multiple goroutines
// (so that it can be returned from Lookup multiple times).
// It serializes calls to the underlying Repo.
type cachingRepo struct {
	path          string
	versionsCache par.ErrCache[string, *Versions]
	statCache     par.ErrCache[string, *RevInfo]
	latestCache   par.ErrCache[struct{}, *RevInfo]
	gomodCache    par.ErrCache[string, []byte]

	once     sync.Once
	initRepo func(context.Context) (Repo, error)
	r        Repo
}

func newCachingRepo(ctx context.Context, path string, initRepo func(context.Context) (Repo, error)) *cachingRepo {
	return &cachingRepo{
		path:     path,
		initRepo: initRepo,
	}
}

func (r *cachingRepo) repo(ctx context.Context) Repo {
	r.once.Do(func() {
		var err error
		r.r, err = r.initRepo(ctx)
		if err != nil {
			r.r = errRepo{r.path, err}
		}
	})
	return r.r
}

func (r *cachingRepo) CheckReuse(ctx context.Context, old *codehost.Origin) error {
	return r.repo(ctx).CheckReuse(ctx, old)
}

func (r *cachingRepo) ModulePath() string {
	return r.path
}

func (r *cachingRepo) Versions(ctx context.Context, prefix string) (*Versions, error) {
	v, err := r.versionsCache.Do(prefix, func() (*Versions, error) {
		return r.repo(ctx).Versions(ctx, prefix)
	})

	if err != nil {
		return nil, err
	}
	return &Versions{
		Origin: v.Origin,
		List:   append([]string(nil), v.List...),
	}, nil
}

type cachedInfo struct {
	info *RevInfo
	err  error
}

func (r *cachingRepo) Stat(ctx context.Context, rev string) (*RevInfo, error) {
	if gover.IsToolchain(r.path) {
		// Skip disk cache; the underlying golang.org/toolchain repo is cached instead.
		return r.repo(ctx).Stat(ctx, rev)
	}
	info, err := r.statCache.Do(rev, func() (*RevInfo, error) {
		file, info, err := readDiskStat(ctx, r.path, rev)
		if err == nil {
			return info, err
		}

		info, err = r.repo(ctx).Stat(ctx, rev)
		if err == nil {
			// If we resolved, say, 1234abcde to v0.0.0-20180604122334-1234abcdef78,
			// then save the information under the proper version, for future use.
			if info.Version != rev {
				file, _ = CachePath(ctx, module.Version{Path: r.path, Version: info.Version}, "info")
				r.statCache.Do(info.Version, func() (*RevInfo, error) {
					return info, nil
				})
			}

			if err := writeDiskStat(ctx, file, info); err != nil {
				fmt.Fprintf(os.Stderr, "go: writing stat cache: %v\n", err)
			}
		}
		return info, err
	})
	if info != nil {
		copy := *info
		info = &copy
	}
	return info, err
}

func (r *cachingRepo) Latest(ctx context.Context) (*RevInfo, error) {
	if gover.IsToolchain(r.path) {
		// Skip disk cache; the underlying golang.org/toolchain repo is cached instead.
		return r.repo(ctx).Latest(ctx)
	}
	info, err := r.latestCache.Do(struct{}{}, func() (*RevInfo, error) {
		info, err := r.repo(ctx).Latest(ctx)

		// Save info for likely future Stat call.
		if err == nil {
			r.statCache.Do(info.Version, func() (*RevInfo, error) {
				return info, nil
			})
			if file, _, err := readDiskStat(ctx, r.path, info.Version); err != nil {
				writeDiskStat(ctx, file, info)
			}
		}

		return info, err
	})
	if info != nil {
		copy := *info
		info = &copy
	}
	return info, err
}

func (r *cachingRepo) GoMod(ctx context.Context, version string) ([]byte, error) {
	if gover.IsToolchain(r.path) {
		// Skip disk cache; the underlying golang.org/toolchain repo is cached instead.
		return r.repo(ctx).GoMod(ctx, version)
	}
	text, err := r.gomodCache.Do(version, func() ([]byte, error) {
		file, text, err := readDiskGoMod(ctx, r.path, version)
		if err == nil {
			// Note: readDiskGoMod already called checkGoMod.
			return text, nil
		}

		text, err = r.repo(ctx).GoMod(ctx, version)
		if err == nil {
			if err := checkGoMod(r.path, version, text); err != nil {
				return text, err
			}
			if err := writeDiskGoMod(ctx, file, text); err != nil {
				fmt.Fprintf(os.Stderr, "go: writing go.mod cache: %v\n", err)
			}
		}
		return text, err
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), text...), nil
}

func (r *cachingRepo) Zip(ctx context.Context, dst io.Writer, version string) error {
	if gover.IsToolchain(r.path) {
		return ErrToolchain
	}
	return r.repo(ctx).Zip(ctx, dst, version)
}

// InfoFile is like Lookup(ctx, path).Stat(version) but also returns the name of the file
// containing the cached information.
func InfoFile(ctx context.Context, path, version string) (*RevInfo, string, error) {
	if !gover.ModIsValid(path, version) {
		return nil, "", fmt.Errorf("invalid version %q", version)
	}

	if file, info, err := readDiskStat(ctx, path, version); err == nil {
		return info, file, nil
	}

	var info *RevInfo
	var err2info map[error]*RevInfo
	err := TryProxies(func(proxy string) error {
		i, err := Lookup(ctx, proxy, path).Stat(ctx, version)
		if err == nil {
			info = i
		} else {
			if err2info == nil {
				err2info = make(map[error]*RevInfo)
			}
			err2info[err] = info
		}
		return err
	})
	if err != nil {
		return err2info[err], "", err
	}

	// Stat should have populated the disk cache for us.
	file, err := CachePath(ctx, module.Version{Path: path, Version: version}, "info")
	if err != nil {
		return nil, "", err
	}
	return info, file, nil
}

// GoMod is like Lookup(ctx, path).GoMod(rev) but avoids the
// repository path resolution in Lookup if the result is
// already cached on local disk.
func GoMod(ctx context.Context, path, rev string) ([]byte, error) {
	// Convert commit hash to pseudo-version
	// to increase cache hit rate.
	if !gover.ModIsValid(path, rev) {
		if _, info, err := readDiskStat(ctx, path, rev); err == nil {
			rev = info.Version
		} else {
			if errors.Is(err, statCacheErr) {
				return nil, err
			}
			err := TryProxies(func(proxy string) error {
				info, err := Lookup(ctx, proxy, path).Stat(ctx, rev)
				if err == nil {
					rev = info.Version
				}
				return err
			})
			if err != nil {
				return nil, err
			}
		}
	}

	_, data, err := readDiskGoMod(ctx, path, rev)
	if err == nil {
		return data, nil
	}

	err = TryProxies(func(proxy string) (err error) {
		data, err = Lookup(ctx, proxy, path).GoMod(ctx, rev)
		return err
	})
	return data, err
}

// GoModFile is like GoMod but returns the name of the file containing
// the cached information.
func GoModFile(ctx context.Context, path, version string) (string, error) {
	if !gover.ModIsValid(path, version) {
		return "", fmt.Errorf("invalid version %q", version)
	}
	if _, err := GoMod(ctx, path, version); err != nil {
		return "", err
	}
	// GoMod should have populated the disk cache for us.
	file, err := CachePath(ctx, module.Version{Path: path, Version: version}, "mod")
	if err != nil {
		return "", err
	}
	return file, nil
}

// GoModSum returns the go.sum entry for the module version's go.mod file.
// (That is, it returns the entry listed in go.sum as "path version/go.mod".)
func GoModSum(ctx context.Context, path, version string) (string, error) {
	if !gover.ModIsValid(path, version) {
		return "", fmt.Errorf("invalid version %q", version)
	}
	data, err := GoMod(ctx, path, version)
	if err != nil {
		return "", err
	}
	sum, err := goModSum(data)
	if err != nil {
		return "", err
	}
	return sum, nil
}

var errNotCached = fmt.Errorf("not in cache")

// readDiskStat reads a cached stat result from disk,
// returning the name of the cache file and the result.
// If the read fails, the caller can use
// writeDiskStat(file, info) to write a new cache entry.
func readDiskStat(ctx context.Context, path, rev string) (file string, info *RevInfo, err error) {
	if gover.IsToolchain(path) {
		return "", nil, errNotCached
	}
	file, data, err := readDiskCache(ctx, path, rev, "info")
	if err != nil {
		// If the cache already contains a pseudo-version with the given hash, we
		// would previously return that pseudo-version without checking upstream.
		// However, that produced an unfortunate side-effect: if the author added a
		// tag to the repository, 'go get' would not pick up the effect of that new
		// tag on the existing commits, and 'go' commands that referred to those
		// commits would use the previous name instead of the new one.
		//
		// That's especially problematic if the original pseudo-version starts with
		// v0.0.0-, as was the case for all pseudo-versions during vgo development,
		// since a v0.0.0- pseudo-version has lower precedence than pretty much any
		// tagged version.
		//
		// In practice, we're only looking up by hash during initial conversion of a
		// legacy config and during an explicit 'go get', and a little extra latency
		// for those operations seems worth the benefit of picking up more accurate
		// versions.
		//
		// Fall back to this resolution scheme only if the GOPROXY setting prohibits
		// us from resolving upstream tags.
		if cfg.GOPROXY == "off" {
			if file, info, err := readDiskStatByHash(ctx, path, rev); err == nil {
				return file, info, nil
			}
		}
		return file, nil, err
	}
	info = new(RevInfo)
	if err := json.Unmarshal(data, info); err != nil {
		return file, nil, errNotCached
	}
	// The disk might have stale .info files that have Name and Short fields set.
	// We want to canonicalize to .info files with those fields omitted.
	// Remarshal and update the cache file if needed.
	data2, err := json.Marshal(info)
	if err == nil && !bytes.Equal(data2, data) {
		writeDiskCache(ctx, file, data)
	}
	return file, info, nil
}

// readDiskStatByHash is a fallback for readDiskStat for the case
// where rev is a commit hash instead of a proper semantic version.
// In that case, we look for a cached pseudo-version that matches
// the commit hash. If we find one, we use it.
// This matters most for converting legacy package management
// configs, when we are often looking up commits by full hash.
// Without this check we'd be doing network I/O to the remote repo
// just to find out about a commit we already know about
// (and have cached under its pseudo-version).
func readDiskStatByHash(ctx context.Context, path, rev string) (file string, info *RevInfo, err error) {
	if gover.IsToolchain(path) {
		return "", nil, errNotCached
	}
	if cfg.GOMODCACHE == "" {
		// Do not download to current directory.
		return "", nil, errNotCached
	}

	if !codehost.AllHex(rev) || len(rev) < 12 {
		return "", nil, errNotCached
	}
	rev = rev[:12]
	cdir, err := cacheDir(ctx, path)
	if err != nil {
		return "", nil, errNotCached
	}
	dir, err := os.Open(cdir)
	if err != nil {
		return "", nil, errNotCached
	}
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return "", nil, errNotCached
	}

	// A given commit hash may map to more than one pseudo-version,
	// depending on which tags are present on the repository.
	// Take the highest such version.
	var maxVersion string
	suffix := "-" + rev + ".info"
	err = errNotCached
	for _, name := range names {
		if strings.HasSuffix(name, suffix) {
			v := strings.TrimSuffix(name, ".info")
			if module.IsPseudoVersion(v) && semver.Compare(v, maxVersion) > 0 {
				maxVersion = v
				file, info, err = readDiskStat(ctx, path, strings.TrimSuffix(name, ".info"))
			}
		}
	}
	return file, info, err
}

// oldVgoPrefix is the prefix in the old auto-generated cached go.mod files.
// We stopped trying to auto-generate the go.mod files. Now we use a trivial
// go.mod with only a module line, and we've dropped the version prefix
// entirely. If we see a version prefix, that means we're looking at an old copy
// and should ignore it.
var oldVgoPrefix = []byte("//vgo 0.0.")

// readDiskGoMod reads a cached go.mod file from disk,
// returning the name of the cache file and the result.
// If the read fails, the caller can use
// writeDiskGoMod(file, data) to write a new cache entry.
func readDiskGoMod(ctx context.Context, path, rev string) (file string, data []byte, err error) {
	if gover.IsToolchain(path) {
		return "", nil, errNotCached
	}
	file, data, err = readDiskCache(ctx, path, rev, "mod")

	// If the file has an old auto-conversion prefix, pretend it's not there.
	if bytes.HasPrefix(data, oldVgoPrefix) {
		err = errNotCached
		data = nil
	}

	if err == nil {
		if err := checkGoMod(path, rev, data); err != nil {
			return "", nil, err
		}
	}

	return file, data, err
}

// readDiskCache is the generic "read from a cache file" implementation.
// It takes the revision and an identifying suffix for the kind of data being cached.
// It returns the name of the cache file and the content of the file.
// If the read fails, the caller can use
// writeDiskCache(file, data) to write a new cache entry.
func readDiskCache(ctx context.Context, path, rev, suffix string) (file string, data []byte, err error) {
	if gover.IsToolchain(path) {
		return "", nil, errNotCached
	}
	file, err = CachePath(ctx, module.Version{Path: path, Version: rev}, suffix)
	if err != nil {
		return "", nil, errNotCached
	}
	data, err = robustio.ReadFile(file)
	if err != nil {
		return file, nil, errNotCached
	}
	return file, data, nil
}

// writeDiskStat writes a stat result cache entry.
// The file name must have been returned by a previous call to readDiskStat.
func writeDiskStat(ctx context.Context, file string, info *RevInfo) error {
	if file == "" {
		return nil
	}

	if info.Origin != nil {
		// Clean the origin information, which might have too many
		// validation criteria, for example if we are saving the result of
		// m@master as m@pseudo-version.
		clean := *info
		info = &clean
		o := *info.Origin
		info.Origin = &o

		// Tags never matter if you are starting with a semver version,
		// as we would be when finding this cache entry.
		o.TagSum = ""
		o.TagPrefix = ""
		// Ref doesn't matter if you have a pseudoversion.
		if module.IsPseudoVersion(info.Version) {
			o.Ref = ""
		}
	}

	js, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return writeDiskCache(ctx, file, js)
}

// writeDiskGoMod writes a go.mod cache entry.
// The file name must have been returned by a previous call to readDiskGoMod.
func writeDiskGoMod(ctx context.Context, file string, text []byte) error {
	return writeDiskCache(ctx, file, text)
}

// writeDiskCache is the generic "write to a cache file" implementation.
// The file must have been returned by a previous call to readDiskCache.
func writeDiskCache(ctx context.Context, file string, data []byte) error {
	if file == "" {
		return nil
	}
	// Make sure directory for file exists.
	if err := os.MkdirAll(filepath.Dir(file), 0777); err != nil {
		return err
	}

	// Write the file to a temporary location, and then rename it to its final
	// path to reduce the likelihood of a corrupt file existing at that final path.
	f, err := tempFile(ctx, filepath.Dir(file), filepath.Base(file), 0666)
	if err != nil {
		return err
	}
	defer func() {
		// Only call os.Remove on f.Name() if we failed to rename it: otherwise,
		// some other process may have created a new file with the same name after
		// the rename completed.
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()

	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := robustio.Rename(f.Name(), file); err != nil {
		return err
	}

	if strings.HasSuffix(file, ".mod") {
		rewriteVersionList(ctx, filepath.Dir(file))
	}
	return nil
}

// tempFile creates a new temporary file with given permission bits.
func tempFile(ctx context.Context, dir, prefix string, perm fs.FileMode) (f *os.File, err error) {
	for i := 0; i < 10000; i++ {
		name := filepath.Join(dir, prefix+strconv.Itoa(rand.Intn(1000000000))+".tmp")
		f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, perm)
		if os.IsExist(err) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		break
	}
	return
}

// rewriteVersionList rewrites the version list in dir
// after a new *.mod file has been written.
func rewriteVersionList(ctx context.Context, dir string) (err error) {
	if filepath.Base(dir) != "@v" {
		base.Fatalf("go: internal error: misuse of rewriteVersionList")
	}

	listFile := filepath.Join(dir, "list")

	// Lock listfile when writing to it to try to avoid corruption to the file.
	// Under rare circumstances, for instance, if the system loses power in the
	// middle of a write it is possible for corrupt data to be written. This is
	// not a problem for the go command itself, but may be an issue if the
	// cache is being served by a GOPROXY HTTP server. This will be corrected
	// the next time a new version of the module is fetched and the file is rewritten.
	// TODO(matloob): golang.org/issue/43313 covers adding a go mod verify
	// command that removes module versions that fail checksums. It should also
	// remove list files that are detected to be corrupt.
	f, err := lockedfile.Edit(listFile)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	infos, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var list []string
	for _, info := range infos {
		// We look for *.mod files on the theory that if we can't supply
		// the .mod file then there's no point in listing that version,
		// since it's unusable. (We can have *.info without *.mod.)
		// We don't require *.zip files on the theory that for code only
		// involved in module graph construction, many *.zip files
		// will never be requested.
		name := info.Name()
		if v, found := strings.CutSuffix(name, ".mod"); found {
			if v != "" && module.CanonicalVersion(v) == v {
				list = append(list, v)
			}
		}
	}
	semver.Sort(list)

	var buf bytes.Buffer
	for _, v := range list {
		buf.WriteString(v)
		buf.WriteString("\n")
	}
	if fi, err := f.Stat(); err == nil && int(fi.Size()) == buf.Len() {
		old := make([]byte, buf.Len()+1)
		if n, err := f.ReadAt(old, 0); err == io.EOF && n == buf.Len() && bytes.Equal(buf.Bytes(), old) {
			return nil // No edit needed.
		}
	}
	// Remove existing contents, so that when we truncate to the actual size it will zero-fill,
	// and we will be able to detect (some) incomplete writes as files containing trailing NUL bytes.
	if err := f.Truncate(0); err != nil {
		return err
	}
	// Reserve the final size and zero-fill.
	if err := f.Truncate(int64(buf.Len())); err != nil {
		return err
	}
	// Write the actual contents. If this fails partway through,
	// the remainder of the file should remain as zeroes.
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Truncate(0)
		return err
	}

	return nil
}

var (
	statCacheOnce sync.Once
	statCacheErr  error

	counterErrorsGOMODCACHEEntryRelative = counter.New("go/errors:gomodcache-entry-relative")
)

// checkCacheDir checks if the directory specified by GOMODCACHE exists. An
// error is returned if it does not.
func checkCacheDir(ctx context.Context) error {
	if cfg.GOMODCACHE == "" {
		// modload.Init exits if GOPATH[0] is empty, and cfg.GOMODCACHE
		// is set to GOPATH[0]/pkg/mod if GOMODCACHE is empty, so this should never happen.
		return fmt.Errorf("module cache not found: neither GOMODCACHE nor GOPATH is set")
	}
	if !filepath.IsAbs(cfg.GOMODCACHE) {
		counterErrorsGOMODCACHEEntryRelative.Inc()
		return fmt.Errorf("GOMODCACHE entry is relative; must be absolute path: %q.\n", cfg.GOMODCACHE)
	}

	// os.Stat is slow on Windows, so we only call it once to prevent unnecessary
	// I/O every time this function is called.
	statCacheOnce.Do(func() {
		fi, err := os.Stat(cfg.GOMODCACHE)
		if err != nil {
			if !os.IsNotExist(err) {
				statCacheErr = fmt.Errorf("could not create module cache: %w", err)
				return
			}
			if err := os.MkdirAll(cfg.GOMODCACHE, 0777); err != nil {
				statCacheErr = fmt.Errorf("could not create module cache: %w", err)
				return
			}
			return
		}
		if !fi.IsDir() {
			statCacheErr = fmt.Errorf("could not create module cache: %q is not a directory", cfg.GOMODCACHE)
			return
		}
	})
	return statCacheErr
}
```