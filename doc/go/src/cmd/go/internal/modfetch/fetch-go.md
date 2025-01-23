Response: The user wants to understand the functionality of the provided Go code snippet.
The code is located in `go/src/cmd/go/internal/modfetch/fetch.go`, suggesting it's related to fetching Go modules.

Here's a breakdown of how to approach this:

1. **Identify Core Functions:** Look for exported functions (capitalized names) as these are the primary entry points and functionalities.
2. **Analyze Function Signatures:**  Pay attention to input parameters (especially context, module.Version) and return values (directory path, error). This gives clues about their purpose.
3. **Examine Internal Functions:**  Understand the helper functions and how they contribute to the core functionalities.
4. **Look for Key Data Structures:**  Identify important variables like `downloadCache`, `downloadZipCache`, and the `goSum` struct. These hold state and manage the module fetching process.
5. **Infer Go Features:**  Based on the functionalities and the imports (like `golang.org/x/mod/module`, `golang.org/x/mod/sumdb`), deduce which Go module-related features are being implemented (e.g., module downloading, verification, go.sum management).
6. **Provide Go Code Examples:**  Illustrate the usage of the identified Go features with simple, practical examples. Include assumptions for input and expected output if applicable.
7. **Explain Command-line Parameter Handling:**  Identify any interaction with command-line parameters through the `cfg` package and explain their effects.
8. **Highlight Potential Pitfalls:** Based on the code logic (especially around caching, locking, and error handling), point out common mistakes users might make.

**Detailed Analysis of the Code:**

* **`Download(ctx context.Context, mod module.Version)`:** This looks like the main function for downloading a module. It uses a cache to avoid redundant downloads. It also checks for toolchain modules and the Go version compatibility.
* **`Unzip(ctx context.Context, mod module.Version, zipfile string)`:**  Similar to `Download`, but it takes a pre-existing zip file as input. This suggests handling cases where the zip is already available locally.
* **`download(ctx context.Context, mod module.Version)`:** This function seems to orchestrate the download process, potentially by first downloading the zip and then unzipping it.
* **`unzip(ctx context.Context, mod module.Version, zipfile string)`:**  Responsible for extracting the module's contents from a zip file into the cache directory. It involves locking to prevent race conditions and handles partial extractions.
* **`DownloadZip(ctx context.Context, mod module.Version)`:** Focuses specifically on downloading the module's zip file to the cache. It also handles zip file hashing and verification.
* **`downloadZip(ctx context.Context, mod module.Version, zipfile string)`:**  The core logic for fetching the zip file, potentially using proxies, and validating its contents.
* **`hashZip(mod module.Version, zipfile, ziphashfile string)`:** Calculates the hash of a zip file and compares it against the go.sum file.
* **`makeDirsReadOnly(dir string)` and `RemoveAll(dir string)`:** Utility functions for managing file permissions in the module cache.
* **`goSum` struct and related functions (e.g., `HaveSum`, `RecordedSum`, `checkModSum`, `WriteGoSum`, `TidyGoSum`, `TrimGoSum`):**  This section is crucial and clearly deals with managing the `go.sum` file, including reading, writing, verifying module checksums, and handling workspace go.sum files.
* **Error Handling:** The code uses custom error types and standard error handling practices.
* **Concurrency:** The use of `sync.Mutex` and `par.ErrCache` suggests consideration for concurrent operations.
* **Command-line Configuration:** The code imports `cmd/go/internal/cfg`, indicating it respects Go command-line flags and environment variables.

Based on this analysis, I can now formulate the description of the code's functionalities, identify the related Go features, provide code examples, explain command-line parameter handling, and highlight potential errors.
这段代码是 Go 语言 `go` 命令的一部分，位于 `go/src/cmd/go/internal/modfetch/fetch.go` 文件中。它的主要功能是**下载和管理 Go 模块及其校验和**。

更具体地说，它实现了以下功能：

1. **模块下载和缓存:**
   - `Download(ctx context.Context, mod module.Version)`: 下载指定的模块版本到本地下载缓存，并返回模块文件树的根目录。它使用 `par.ErrCache` 来避免重复下载。
   - `Unzip(ctx context.Context, mod module.Version, zipfile string)`: 类似于 `Download`，但是使用显式提供的 zip 文件，而不是从网络下载。这主要用于 Go 发行版自带的 GOFIPS140 zip 文件。
   - `DownloadZip(ctx context.Context, mod module.Version)`: 下载指定模块版本的 zip 文件到本地 zip 缓存，并返回 zip 文件的路径。它也使用 `par.ErrCache` 来避免重复下载。

2. **模块文件解压:**
   - `unzip(ctx context.Context, mod module.Version, zipfile string)`: 将模块的 zip 文件解压到缓存目录。它使用锁机制 (`lockVersion`) 来保证并发安全，并创建 `.partial` 文件来防止在解压过程中被其他进程读取不完整的数据。

3. **模块校验和管理 (go.sum 文件):**
   - `HaveSum(mod module.Version)`: 检查 `go.sum` 文件是否包含指定模块的条目。
   - `RecordedSum(mod module.Version)`: 返回 `go.sum` 文件中指定模块的校验和。
   - `checkMod(ctx context.Context, mod module.Version)`: 检查已下载模块的校验和是否与 `go.sum` 文件中的记录匹配。
   - `checkGoMod(path, version string, data []byte)`: 检查指定 `go.mod` 内容的校验和是否与 `go.sum` 文件中的记录匹配。
   - `checkModSum(mod module.Version, h string)`: 检查给定模块的校验和 `h` 是否与 `go.sum` 文件中的记录匹配，并处理校验和数据库的交互。
   - `WriteGoSum(ctx context.Context, keep map[module.Version]bool, readonly bool)`: 如果需要更新，则写入 `go.sum` 文件。`keep` 参数用于指示哪些模块的校验和应该保留。
   - `TidyGoSum(keep map[module.Version]bool)`: 返回一个整理过的 `go.sum` 文件的内容。
   - `TrimGoSum(keep map[module.Version]bool)`: 裁剪 `go.sum` 文件，只保留可重现构建所需的模块校验和。

4. **模块缓存管理:**
   - `DownloadDir(ctx context.Context, mod module.Version)`: 计算并返回指定模块版本在本地下载缓存中的目录。
   - `CachePath(ctx context.Context, mod module.Version, suffix string)`: 计算并返回指定模块版本在本地缓存中的文件路径，例如 zip 文件或 ziphash 文件。
   - `RemoveAll(dir string)`: 删除由 `Download` 或 `Unzip` 创建的目录，并处理权限问题。
   - `makeDirsReadOnly(dir string)`: 尝试将目录及其内容设置为只读。

5. **与其他组件的交互:**
   - 使用 `cmd/go/internal/base` 进行错误处理和输出。
   - 使用 `cmd/go/internal/cfg` 获取配置信息，例如 `GOMODCACHE`。
   - 使用 `cmd/go/internal/fsys` 处理文件系统操作，特别是 overlay 文件系统。
   - 使用 `golang.org/x/mod/module` 表示模块的版本信息。
   - 使用 `golang.org/x/mod/sumdb` 与校验和数据库交互。
   - 使用 `golang.org/x/mod/zip` 处理 zip 文件的解压。
   - 使用 `cmd/internal/par` 实现并行缓存。
   - 使用 `cmd/internal/robustio` 提供健壮的文件系统操作。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 **Go 模块系统的模块下载和校验功能**。它负责从模块源下载模块代码，并使用 `go.sum` 文件来验证下载的模块是否未被篡改，从而保证构建的可信度和安全性。

**Go 代码举例说明:**

假设我们要下载 `golang.org/x/text` 模块的 `v0.3.7` 版本。可以使用 `modfetch.Download` 函数：

```go
package main

import (
	"context"
	"fmt"
	"log"

	"cmd/go/internal/modfetch"
	"golang.org/x/mod/module"
)

func main() {
	mod := module.Version{Path: "golang.org/x/text", Version: "v0.3.7"}
	dir, err := modfetch.Download(context.Background(), mod)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("模块下载到:", dir)

	// 假设输入了正确的模块名和版本号
	// 输出示例:
	// 模块下载到: /Users/yourusername/go/pkg/mod/cache/download/golang.org/x/text/@v/v0.3.7
}
```

**代码推理示例:**

假设我们调用 `Download` 函数下载 `example.com/foo@v1.2.3` 模块。

**假设输入:**

```go
mod := module.Version{Path: "example.com/foo", Version: "v1.2.3"}
```

**推理过程:**

1. `Download` 函数首先检查是否是工具链模块。
2. 然后检查缓存目录是否已初始化。
3. 它尝试从 `downloadCache` 中获取结果。如果缓存中没有，则执行传入的 `func()`。
4. 在 `func()` 中，`download` 函数会被调用。
5. `download` 函数首先尝试从缓存中获取已解压的目录。
6. 如果缓存中没有已解压的目录，则调用 `DownloadZip` 下载 zip 文件。
7. `DownloadZip` 也会检查缓存，如果 zip 文件不存在，则会从模块源下载。
8. 下载完成后，`unzip` 函数会被调用，将 zip 文件解压到缓存目录。
9. 解压过程中，会创建 `.partial` 文件，并在解压完成后删除。
10. 解压完成后，`checkMod` 函数会被调用，验证下载的模块的校验和。
11. 最后，`Download` 函数将缓存解压后的目录路径并返回。

**假设输出 (成功下载并解压):**

```
/Users/yourusername/go/pkg/mod/cache/download/example.com/foo/@v/v1.2.3
```

**涉及的命令行参数的具体处理:**

这段代码中直接处理的命令行参数较少，它主要依赖于 `cmd/go/internal/cfg` 包来获取 Go 命令的配置信息，这些配置信息通常由用户通过命令行参数或环境变量设置。一些重要的配置参数包括：

- **`-mod`**: 控制模块模式（例如 `-mod=readonly`）。`WriteGoSum` 函数会根据 `-mod=readonly` 的设置来决定是否允许修改 `go.sum` 文件。
- **`-overlay`**: 指定 overlay 文件。`readGoSumFile` 函数会检查 `go.sum` 文件是否在 overlay 中，如果在则不会进行文件锁定。
- **`-modcache`**: 指定模块缓存路径。虽然代码中没有直接处理这个参数，但 `CachePath` 函数会根据 `cfg.GOMODCACHE` 的值来计算缓存路径。

其他一些环境变量也会影响这段代码的行为，例如：

- **`GOPATH`**:  影响模块缓存的默认位置。
- **`GOMODCACHE`**: 指定模块缓存的位置。
- **`GOPROXY`**:  指定模块代理服务器。`TryProxies` 函数会根据 `GOPROXY` 的设置尝试从不同的代理下载模块。
- **`GOSUMDB`**: 指定校验和数据库。`checkSumDB` 函数会根据 `GOSUMDB` 的设置来决定是否与校验和数据库交互。
- **`GOPRIVATE` / `GONOPROXY` / `GONOSUMDB`**:  用于控制哪些模块被认为是私有的，以及是否使用代理和校验和数据库。这些环境变量会影响 `useSumDB` 和 `lookupSumDB` 的行为。

**使用者易犯错的点:**

1. **手动修改 `go.sum` 文件:** 用户可能会尝试手动编辑 `go.sum` 文件来添加或删除校验和。这可能会导致 `go` 命令在后续操作中报告校验和不匹配的错误，因为手动修改可能引入错误或与实际下载的模块内容不符。
   ```
   // 错误示例：手动编辑 go.sum 文件
   // go.sum 文件内容被错误修改
   ```
   **后果:** 运行 `go build` 或 `go test` 等命令时可能会报错：
   ```
   verifying example.com/some/module@v1.0.0: checksum mismatch
    downloaded: h1:incorrecthash
    go.sum:     h1:correcthash
   ```

2. **缓存问题:**  用户可能遇到缓存问题，例如缓存损坏或过期，导致下载或校验失败。
   ```
   // 错误示例：模块缓存损坏
   ```
   **解决方法:** 可以使用 `go clean -modcache` 命令清除模块缓存。

3. **网络问题:**  下载模块时可能会遇到网络问题，导致下载失败或校验和不匹配。
   ```
   // 错误示例：网络连接不稳定导致下载不完整
   ```
   **解决方法:** 检查网络连接，或者配置合适的 `GOPROXY`。

4. **只读模式下的 `go.sum` 修改:**  如果在 `-mod=readonly` 模式下尝试更新 `go.sum` 文件，将会失败。
   ```
   // 错误示例：在 -mod=readonly 模式下运行需要更新 go.sum 的命令
   // go build -mod=readonly
   ```
   **后果:** 会出现类似以下的错误：
   ```
   go: updates to go.sum needed, disabled by -mod=readonly
   ```

这段代码是 Go 模块系统核心功能的重要组成部分，它确保了模块下载的安全性、一致性和可重现性。理解其功能对于深入理解 Go 模块的工作原理至关重要。

### 提示词
```
这是路径为go/src/cmd/go/internal/modfetch/fetch.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"cmd/go/internal/base"
	"cmd/go/internal/cfg"
	"cmd/go/internal/fsys"
	"cmd/go/internal/gover"
	"cmd/go/internal/lockedfile"
	"cmd/go/internal/str"
	"cmd/go/internal/trace"
	"cmd/internal/par"
	"cmd/internal/robustio"

	"golang.org/x/mod/module"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"
)

var downloadCache par.ErrCache[module.Version, string] // version → directory

var ErrToolchain = errors.New("internal error: invalid operation on toolchain module")

// Download downloads the specific module version to the
// local download cache and returns the name of the directory
// corresponding to the root of the module's file tree.
func Download(ctx context.Context, mod module.Version) (dir string, err error) {
	if gover.IsToolchain(mod.Path) {
		return "", ErrToolchain
	}
	if err := checkCacheDir(ctx); err != nil {
		base.Fatal(err)
	}

	// The par.Cache here avoids duplicate work.
	return downloadCache.Do(mod, func() (string, error) {
		dir, err := download(ctx, mod)
		if err != nil {
			return "", err
		}
		checkMod(ctx, mod)

		// If go.mod exists (not an old legacy module), check version is not too new.
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			goVersion := gover.GoModLookup(data, "go")
			if gover.Compare(goVersion, gover.Local()) > 0 {
				return "", &gover.TooNewError{What: mod.String(), GoVersion: goVersion}
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}

		return dir, nil
	})
}

// Unzip is like Download but is given the explicit zip file to use,
// rather than downloading it. This is used for the GOFIPS140 zip files,
// which ship in the Go distribution itself.
func Unzip(ctx context.Context, mod module.Version, zipfile string) (dir string, err error) {
	if err := checkCacheDir(ctx); err != nil {
		base.Fatal(err)
	}

	return downloadCache.Do(mod, func() (string, error) {
		ctx, span := trace.StartSpan(ctx, "modfetch.Unzip "+mod.String())
		defer span.Done()

		dir, err = DownloadDir(ctx, mod)
		if err == nil {
			// The directory has already been completely extracted (no .partial file exists).
			return dir, nil
		} else if dir == "" || !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}

		return unzip(ctx, mod, zipfile)
	})
}

func download(ctx context.Context, mod module.Version) (dir string, err error) {
	ctx, span := trace.StartSpan(ctx, "modfetch.download "+mod.String())
	defer span.Done()

	dir, err = DownloadDir(ctx, mod)
	if err == nil {
		// The directory has already been completely extracted (no .partial file exists).
		return dir, nil
	} else if dir == "" || !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	// To avoid cluttering the cache with extraneous files,
	// DownloadZip uses the same lockfile as Download.
	// Invoke DownloadZip before locking the file.
	zipfile, err := DownloadZip(ctx, mod)
	if err != nil {
		return "", err
	}

	return unzip(ctx, mod, zipfile)
}

func unzip(ctx context.Context, mod module.Version, zipfile string) (dir string, err error) {
	unlock, err := lockVersion(ctx, mod)
	if err != nil {
		return "", err
	}
	defer unlock()

	ctx, span := trace.StartSpan(ctx, "unzip "+zipfile)
	defer span.Done()

	// Check whether the directory was populated while we were waiting on the lock.
	dir, dirErr := DownloadDir(ctx, mod)
	if dirErr == nil {
		return dir, nil
	}
	_, dirExists := dirErr.(*DownloadDirPartialError)

	// Clean up any remaining temporary directories created by old versions
	// (before 1.16), as well as partially extracted directories (indicated by
	// DownloadDirPartialError, usually because of a .partial file). This is only
	// safe to do because the lock file ensures that their writers are no longer
	// active.
	parentDir := filepath.Dir(dir)
	tmpPrefix := filepath.Base(dir) + ".tmp-"
	if old, err := filepath.Glob(filepath.Join(str.QuoteGlob(parentDir), str.QuoteGlob(tmpPrefix)+"*")); err == nil {
		for _, path := range old {
			RemoveAll(path) // best effort
		}
	}
	if dirExists {
		if err := RemoveAll(dir); err != nil {
			return "", err
		}
	}

	partialPath, err := CachePath(ctx, mod, "partial")
	if err != nil {
		return "", err
	}

	// Extract the module zip directory at its final location.
	//
	// To prevent other processes from reading the directory if we crash,
	// create a .partial file before extracting the directory, and delete
	// the .partial file afterward (all while holding the lock).
	//
	// Before Go 1.16, we extracted to a temporary directory with a random name
	// then renamed it into place with os.Rename. On Windows, this failed with
	// ERROR_ACCESS_DENIED when another process (usually an anti-virus scanner)
	// opened files in the temporary directory.
	//
	// Go 1.14.2 and higher respect .partial files. Older versions may use
	// partially extracted directories. 'go mod verify' can detect this,
	// and 'go clean -modcache' can fix it.
	if err := os.MkdirAll(parentDir, 0777); err != nil {
		return "", err
	}
	if err := os.WriteFile(partialPath, nil, 0666); err != nil {
		return "", err
	}
	if err := modzip.Unzip(dir, mod, zipfile); err != nil {
		fmt.Fprintf(os.Stderr, "-> %s\n", err)
		if rmErr := RemoveAll(dir); rmErr == nil {
			os.Remove(partialPath)
		}
		return "", err
	}
	if err := os.Remove(partialPath); err != nil {
		return "", err
	}

	if !cfg.ModCacheRW {
		makeDirsReadOnly(dir)
	}
	return dir, nil
}

var downloadZipCache par.ErrCache[module.Version, string]

// DownloadZip downloads the specific module version to the
// local zip cache and returns the name of the zip file.
func DownloadZip(ctx context.Context, mod module.Version) (zipfile string, err error) {
	// The par.Cache here avoids duplicate work.
	return downloadZipCache.Do(mod, func() (string, error) {
		zipfile, err := CachePath(ctx, mod, "zip")
		if err != nil {
			return "", err
		}
		ziphashfile := zipfile + "hash"

		// Return without locking if the zip and ziphash files exist.
		if _, err := os.Stat(zipfile); err == nil {
			if _, err := os.Stat(ziphashfile); err == nil {
				return zipfile, nil
			}
		}

		// The zip or ziphash file does not exist. Acquire the lock and create them.
		if cfg.CmdName != "mod download" {
			vers := mod.Version
			if mod.Path == "golang.org/toolchain" {
				// Shorten v0.0.1-go1.13.1.darwin-amd64 to go1.13.1.darwin-amd64
				_, vers, _ = strings.Cut(vers, "-")
				if i := strings.LastIndex(vers, "."); i >= 0 {
					goos, goarch, _ := strings.Cut(vers[i+1:], "-")
					vers = vers[:i] + " (" + goos + "/" + goarch + ")"
				}
				fmt.Fprintf(os.Stderr, "go: downloading %s\n", vers)
			} else {
				fmt.Fprintf(os.Stderr, "go: downloading %s %s\n", mod.Path, vers)
			}
		}
		unlock, err := lockVersion(ctx, mod)
		if err != nil {
			return "", err
		}
		defer unlock()

		if err := downloadZip(ctx, mod, zipfile); err != nil {
			return "", err
		}
		return zipfile, nil
	})
}

func downloadZip(ctx context.Context, mod module.Version, zipfile string) (err error) {
	ctx, span := trace.StartSpan(ctx, "modfetch.downloadZip "+zipfile)
	defer span.Done()

	// Double-check that the zipfile was not created while we were waiting for
	// the lock in DownloadZip.
	ziphashfile := zipfile + "hash"
	var zipExists, ziphashExists bool
	if _, err := os.Stat(zipfile); err == nil {
		zipExists = true
	}
	if _, err := os.Stat(ziphashfile); err == nil {
		ziphashExists = true
	}
	if zipExists && ziphashExists {
		return nil
	}

	// Create parent directories.
	if err := os.MkdirAll(filepath.Dir(zipfile), 0777); err != nil {
		return err
	}

	// Clean up any remaining tempfiles from previous runs.
	// This is only safe to do because the lock file ensures that their
	// writers are no longer active.
	tmpPattern := filepath.Base(zipfile) + "*.tmp"
	if old, err := filepath.Glob(filepath.Join(str.QuoteGlob(filepath.Dir(zipfile)), tmpPattern)); err == nil {
		for _, path := range old {
			os.Remove(path) // best effort
		}
	}

	// If the zip file exists, the ziphash file must have been deleted
	// or lost after a file system crash. Re-hash the zip without downloading.
	if zipExists {
		return hashZip(mod, zipfile, ziphashfile)
	}

	// From here to the os.Rename call below is functionally almost equivalent to
	// renameio.WriteToFile, with one key difference: we want to validate the
	// contents of the file (by hashing it) before we commit it. Because the file
	// is zip-compressed, we need an actual file — or at least an io.ReaderAt — to
	// validate it: we can't just tee the stream as we write it.
	f, err := tempFile(ctx, filepath.Dir(zipfile), filepath.Base(zipfile), 0666)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()

	var unrecoverableErr error
	err = TryProxies(func(proxy string) error {
		if unrecoverableErr != nil {
			return unrecoverableErr
		}
		repo := Lookup(ctx, proxy, mod.Path)
		err := repo.Zip(ctx, f, mod.Version)
		if err != nil {
			// Zip may have partially written to f before failing.
			// (Perhaps the server crashed while sending the file?)
			// Since we allow fallback on error in some cases, we need to fix up the
			// file to be empty again for the next attempt.
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				unrecoverableErr = err
				return err
			}
			if err := f.Truncate(0); err != nil {
				unrecoverableErr = err
				return err
			}
		}
		return err
	})
	if err != nil {
		return err
	}

	// Double-check that the paths within the zip file are well-formed.
	//
	// TODO(bcmills): There is a similar check within the Unzip function. Can we eliminate one?
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	z, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return err
	}
	prefix := mod.Path + "@" + mod.Version + "/"
	for _, f := range z.File {
		if !strings.HasPrefix(f.Name, prefix) {
			return fmt.Errorf("zip for %s has unexpected file %s", prefix[:len(prefix)-1], f.Name)
		}
	}

	if err := f.Close(); err != nil {
		return err
	}

	// Hash the zip file and check the sum before renaming to the final location.
	if err := hashZip(mod, f.Name(), ziphashfile); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), zipfile); err != nil {
		return err
	}

	// TODO(bcmills): Should we make the .zip and .ziphash files read-only to discourage tampering?

	return nil
}

// hashZip reads the zip file opened in f, then writes the hash to ziphashfile,
// overwriting that file if it exists.
//
// If the hash does not match go.sum (or the sumdb if enabled), hashZip returns
// an error and does not write ziphashfile.
func hashZip(mod module.Version, zipfile, ziphashfile string) (err error) {
	hash, err := dirhash.HashZip(zipfile, dirhash.DefaultHash)
	if err != nil {
		return err
	}
	if err := checkModSum(mod, hash); err != nil {
		return err
	}
	hf, err := lockedfile.Create(ziphashfile)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := hf.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	if err := hf.Truncate(int64(len(hash))); err != nil {
		return err
	}
	if _, err := hf.WriteAt([]byte(hash), 0); err != nil {
		return err
	}
	return nil
}

// makeDirsReadOnly makes a best-effort attempt to remove write permissions for dir
// and its transitive contents.
func makeDirsReadOnly(dir string) {
	type pathMode struct {
		path string
		mode fs.FileMode
	}
	var dirs []pathMode // in lexical order
	filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			info, err := d.Info()
			if err == nil && info.Mode()&0222 != 0 {
				dirs = append(dirs, pathMode{path, info.Mode()})
			}
		}
		return nil
	})

	// Run over list backward to chmod children before parents.
	for i := len(dirs) - 1; i >= 0; i-- {
		os.Chmod(dirs[i].path, dirs[i].mode&^0222)
	}
}

// RemoveAll removes a directory written by Download or Unzip, first applying
// any permission changes needed to do so.
func RemoveAll(dir string) error {
	// Module cache has 0555 directories; make them writable in order to remove content.
	filepath.WalkDir(dir, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return nil // ignore errors walking in file system
		}
		if info.IsDir() {
			os.Chmod(path, 0777)
		}
		return nil
	})
	return robustio.RemoveAll(dir)
}

var GoSumFile string             // path to go.sum; set by package modload
var WorkspaceGoSumFiles []string // path to module go.sums in workspace; set by package modload

type modSum struct {
	mod module.Version
	sum string
}

var goSum struct {
	mu        sync.Mutex
	m         map[module.Version][]string            // content of go.sum file
	w         map[string]map[module.Version][]string // sum file in workspace -> content of that sum file
	status    map[modSum]modSumStatus                // state of sums in m
	overwrite bool                                   // if true, overwrite go.sum without incorporating its contents
	enabled   bool                                   // whether to use go.sum at all
}

type modSumStatus struct {
	used, dirty bool
}

// Reset resets globals in the modfetch package, so previous loads don't affect
// contents of go.sum files.
func Reset() {
	GoSumFile = ""
	WorkspaceGoSumFiles = nil

	// Uses of lookupCache and downloadCache both can call checkModSum,
	// which in turn sets the used bit on goSum.status for modules.
	// Reset them so used can be computed properly.
	lookupCache = par.Cache[lookupCacheKey, Repo]{}
	downloadCache = par.ErrCache[module.Version, string]{}

	// Clear all fields on goSum. It will be initialized later
	goSum.mu.Lock()
	goSum.m = nil
	goSum.w = nil
	goSum.status = nil
	goSum.overwrite = false
	goSum.enabled = false
	goSum.mu.Unlock()
}

// initGoSum initializes the go.sum data.
// The boolean it returns reports whether the
// use of go.sum is now enabled.
// The goSum lock must be held.
func initGoSum() (bool, error) {
	if GoSumFile == "" {
		return false, nil
	}
	if goSum.m != nil {
		return true, nil
	}

	goSum.m = make(map[module.Version][]string)
	goSum.status = make(map[modSum]modSumStatus)
	goSum.w = make(map[string]map[module.Version][]string)

	for _, f := range WorkspaceGoSumFiles {
		goSum.w[f] = make(map[module.Version][]string)
		_, err := readGoSumFile(goSum.w[f], f)
		if err != nil {
			return false, err
		}
	}

	enabled, err := readGoSumFile(goSum.m, GoSumFile)
	goSum.enabled = enabled
	return enabled, err
}

func readGoSumFile(dst map[module.Version][]string, file string) (bool, error) {
	var (
		data []byte
		err  error
	)
	if fsys.Replaced(file) {
		// Don't lock go.sum if it's part of the overlay.
		// On Plan 9, locking requires chmod, and we don't want to modify any file
		// in the overlay. See #44700.
		data, err = os.ReadFile(fsys.Actual(file))
	} else {
		data, err = lockedfile.Read(file)
	}
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	readGoSum(dst, file, data)

	return true, nil
}

// emptyGoModHash is the hash of a 1-file tree containing a 0-length go.mod.
// A bug caused us to write these into go.sum files for non-modules.
// We detect and remove them.
const emptyGoModHash = "h1:G7mAYYxgmS0lVkHyy2hEOLQCFB0DlQFTMLWggykrydY="

// readGoSum parses data, which is the content of file,
// and adds it to goSum.m. The goSum lock must be held.
func readGoSum(dst map[module.Version][]string, file string, data []byte) {
	lineno := 0
	for len(data) > 0 {
		var line []byte
		lineno++
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			line, data = data, nil
		} else {
			line, data = data[:i], data[i+1:]
		}
		f := strings.Fields(string(line))
		if len(f) == 0 {
			// blank line; skip it
			continue
		}
		if len(f) != 3 {
			if cfg.CmdName == "mod tidy" {
				// ignore malformed line so that go mod tidy can fix go.sum
				continue
			} else {
				base.Fatalf("malformed go.sum:\n%s:%d: wrong number of fields %v\n", file, lineno, len(f))
			}
		}
		if f[2] == emptyGoModHash {
			// Old bug; drop it.
			continue
		}
		mod := module.Version{Path: f[0], Version: f[1]}
		dst[mod] = append(dst[mod], f[2])
	}
}

// HaveSum returns true if the go.sum file contains an entry for mod.
// The entry's hash must be generated with a known hash algorithm.
// mod.Version may have a "/go.mod" suffix to distinguish sums for
// .mod and .zip files.
func HaveSum(mod module.Version) bool {
	goSum.mu.Lock()
	defer goSum.mu.Unlock()
	inited, err := initGoSum()
	if err != nil || !inited {
		return false
	}
	for _, goSums := range goSum.w {
		for _, h := range goSums[mod] {
			if !strings.HasPrefix(h, "h1:") {
				continue
			}
			if !goSum.status[modSum{mod, h}].dirty {
				return true
			}
		}
	}
	for _, h := range goSum.m[mod] {
		if !strings.HasPrefix(h, "h1:") {
			continue
		}
		if !goSum.status[modSum{mod, h}].dirty {
			return true
		}
	}
	return false
}

// RecordedSum returns the sum if the go.sum file contains an entry for mod.
// The boolean reports true if an entry was found or
// false if no entry found or two conflicting sums are found.
// The entry's hash must be generated with a known hash algorithm.
// mod.Version may have a "/go.mod" suffix to distinguish sums for
// .mod and .zip files.
func RecordedSum(mod module.Version) (sum string, ok bool) {
	goSum.mu.Lock()
	defer goSum.mu.Unlock()
	inited, err := initGoSum()
	foundSum := ""
	if err != nil || !inited {
		return "", false
	}
	for _, goSums := range goSum.w {
		for _, h := range goSums[mod] {
			if !strings.HasPrefix(h, "h1:") {
				continue
			}
			if !goSum.status[modSum{mod, h}].dirty {
				if foundSum != "" && foundSum != h { // conflicting sums exist
					return "", false
				}
				foundSum = h
			}
		}
	}
	for _, h := range goSum.m[mod] {
		if !strings.HasPrefix(h, "h1:") {
			continue
		}
		if !goSum.status[modSum{mod, h}].dirty {
			if foundSum != "" && foundSum != h { // conflicting sums exist
				return "", false
			}
			foundSum = h
		}
	}
	return foundSum, true
}

// checkMod checks the given module's checksum and Go version.
func checkMod(ctx context.Context, mod module.Version) {
	// Do the file I/O before acquiring the go.sum lock.
	ziphash, err := CachePath(ctx, mod, "ziphash")
	if err != nil {
		base.Fatalf("verifying %v", module.VersionError(mod, err))
	}
	data, err := lockedfile.Read(ziphash)
	if err != nil {
		base.Fatalf("verifying %v", module.VersionError(mod, err))
	}
	data = bytes.TrimSpace(data)
	if !isValidSum(data) {
		// Recreate ziphash file from zip file and use that to check the mod sum.
		zip, err := CachePath(ctx, mod, "zip")
		if err != nil {
			base.Fatalf("verifying %v", module.VersionError(mod, err))
		}
		err = hashZip(mod, zip, ziphash)
		if err != nil {
			base.Fatalf("verifying %v", module.VersionError(mod, err))
		}
		return
	}
	h := string(data)
	if !strings.HasPrefix(h, "h1:") {
		base.Fatalf("verifying %v", module.VersionError(mod, fmt.Errorf("unexpected ziphash: %q", h)))
	}

	if err := checkModSum(mod, h); err != nil {
		base.Fatalf("%s", err)
	}
}

// goModSum returns the checksum for the go.mod contents.
func goModSum(data []byte) (string, error) {
	return dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
}

// checkGoMod checks the given module's go.mod checksum;
// data is the go.mod content.
func checkGoMod(path, version string, data []byte) error {
	h, err := goModSum(data)
	if err != nil {
		return &module.ModuleError{Path: path, Version: version, Err: fmt.Errorf("verifying go.mod: %v", err)}
	}

	return checkModSum(module.Version{Path: path, Version: version + "/go.mod"}, h)
}

// checkModSum checks that the recorded checksum for mod is h.
//
// mod.Version may have the additional suffix "/go.mod" to request the checksum
// for the module's go.mod file only.
func checkModSum(mod module.Version, h string) error {
	// We lock goSum when manipulating it,
	// but we arrange to release the lock when calling checkSumDB,
	// so that parallel calls to checkModHash can execute parallel calls
	// to checkSumDB.

	// Check whether mod+h is listed in go.sum already. If so, we're done.
	goSum.mu.Lock()
	inited, err := initGoSum()
	if err != nil {
		goSum.mu.Unlock()
		return err
	}
	done := inited && haveModSumLocked(mod, h)
	if inited {
		st := goSum.status[modSum{mod, h}]
		st.used = true
		goSum.status[modSum{mod, h}] = st
	}
	goSum.mu.Unlock()

	if done {
		return nil
	}

	// Not listed, so we want to add them.
	// Consult checksum database if appropriate.
	if useSumDB(mod) {
		// Calls base.Fatalf if mismatch detected.
		if err := checkSumDB(mod, h); err != nil {
			return err
		}
	}

	// Add mod+h to go.sum, if it hasn't appeared already.
	if inited {
		goSum.mu.Lock()
		addModSumLocked(mod, h)
		st := goSum.status[modSum{mod, h}]
		st.dirty = true
		goSum.status[modSum{mod, h}] = st
		goSum.mu.Unlock()
	}
	return nil
}

// haveModSumLocked reports whether the pair mod,h is already listed in go.sum.
// If it finds a conflicting pair instead, it calls base.Fatalf.
// goSum.mu must be locked.
func haveModSumLocked(mod module.Version, h string) bool {
	sumFileName := "go.sum"
	if strings.HasSuffix(GoSumFile, "go.work.sum") {
		sumFileName = "go.work.sum"
	}
	for _, vh := range goSum.m[mod] {
		if h == vh {
			return true
		}
		if strings.HasPrefix(vh, "h1:") {
			base.Fatalf("verifying %s@%s: checksum mismatch\n\tdownloaded: %v\n\t%s:     %v"+goSumMismatch, mod.Path, mod.Version, h, sumFileName, vh)
		}
	}
	// Also check workspace sums.
	foundMatch := false
	// Check sums from all files in case there are conflicts between
	// the files.
	for goSumFile, goSums := range goSum.w {
		for _, vh := range goSums[mod] {
			if h == vh {
				foundMatch = true
			} else if strings.HasPrefix(vh, "h1:") {
				base.Fatalf("verifying %s@%s: checksum mismatch\n\tdownloaded: %v\n\t%s:     %v"+goSumMismatch, mod.Path, mod.Version, h, goSumFile, vh)
			}
		}
	}
	return foundMatch
}

// addModSumLocked adds the pair mod,h to go.sum.
// goSum.mu must be locked.
func addModSumLocked(mod module.Version, h string) {
	if haveModSumLocked(mod, h) {
		return
	}
	if len(goSum.m[mod]) > 0 {
		fmt.Fprintf(os.Stderr, "warning: verifying %s@%s: unknown hashes in go.sum: %v; adding %v"+hashVersionMismatch, mod.Path, mod.Version, strings.Join(goSum.m[mod], ", "), h)
	}
	goSum.m[mod] = append(goSum.m[mod], h)
}

// checkSumDB checks the mod, h pair against the Go checksum database.
// It calls base.Fatalf if the hash is to be rejected.
func checkSumDB(mod module.Version, h string) error {
	modWithoutSuffix := mod
	noun := "module"
	if before, found := strings.CutSuffix(mod.Version, "/go.mod"); found {
		noun = "go.mod"
		modWithoutSuffix.Version = before
	}

	db, lines, err := lookupSumDB(mod)
	if err != nil {
		return module.VersionError(modWithoutSuffix, fmt.Errorf("verifying %s: %v", noun, err))
	}

	have := mod.Path + " " + mod.Version + " " + h
	prefix := mod.Path + " " + mod.Version + " h1:"
	for _, line := range lines {
		if line == have {
			return nil
		}
		if strings.HasPrefix(line, prefix) {
			return module.VersionError(modWithoutSuffix, fmt.Errorf("verifying %s: checksum mismatch\n\tdownloaded: %v\n\t%s: %v"+sumdbMismatch, noun, h, db, line[len(prefix)-len("h1:"):]))
		}
	}
	return nil
}

// Sum returns the checksum for the downloaded copy of the given module,
// if present in the download cache.
func Sum(ctx context.Context, mod module.Version) string {
	if cfg.GOMODCACHE == "" {
		// Do not use current directory.
		return ""
	}

	ziphash, err := CachePath(ctx, mod, "ziphash")
	if err != nil {
		return ""
	}
	data, err := lockedfile.Read(ziphash)
	if err != nil {
		return ""
	}
	data = bytes.TrimSpace(data)
	if !isValidSum(data) {
		return ""
	}
	return string(data)
}

// isValidSum returns true if data is the valid contents of a zip hash file.
// Certain critical files are written to disk by first truncating
// then writing the actual bytes, so that if the write fails
// the corrupt file should contain at least one of the null
// bytes written by the truncate operation.
func isValidSum(data []byte) bool {
	if bytes.IndexByte(data, '\000') >= 0 {
		return false
	}

	if len(data) != len("h1:")+base64.StdEncoding.EncodedLen(sha256.Size) {
		return false
	}

	return true
}

var ErrGoSumDirty = errors.New("updates to go.sum needed, disabled by -mod=readonly")

// WriteGoSum writes the go.sum file if it needs to be updated.
//
// keep is used to check whether a newly added sum should be saved in go.sum.
// It should have entries for both module content sums and go.mod sums
// (version ends with "/go.mod"). Existing sums will be preserved unless they
// have been marked for deletion with TrimGoSum.
func WriteGoSum(ctx context.Context, keep map[module.Version]bool, readonly bool) error {
	goSum.mu.Lock()
	defer goSum.mu.Unlock()

	// If we haven't read the go.sum file yet, don't bother writing it.
	if !goSum.enabled {
		return nil
	}

	// Check whether we need to add sums for which keep[m] is true or remove
	// unused sums marked with TrimGoSum. If there are no changes to make,
	// just return without opening go.sum.
	dirty := false
Outer:
	for m, hs := range goSum.m {
		for _, h := range hs {
			st := goSum.status[modSum{m, h}]
			if st.dirty && (!st.used || keep[m]) {
				dirty = true
				break Outer
			}
		}
	}
	if !dirty {
		return nil
	}
	if readonly {
		return ErrGoSumDirty
	}
	if fsys.Replaced(GoSumFile) {
		base.Fatalf("go: updates to go.sum needed, but go.sum is part of the overlay specified with -overlay")
	}

	// Make a best-effort attempt to acquire the side lock, only to exclude
	// previous versions of the 'go' command from making simultaneous edits.
	if unlock, err := SideLock(ctx); err == nil {
		defer unlock()
	}

	err := lockedfile.Transform(GoSumFile, func(data []byte) ([]byte, error) {
		tidyGoSum := tidyGoSum(data, keep)
		return tidyGoSum, nil
	})

	if err != nil {
		return fmt.Errorf("updating go.sum: %w", err)
	}

	goSum.status = make(map[modSum]modSumStatus)
	goSum.overwrite = false
	return nil
}

// TidyGoSum returns a tidy version of the go.sum file.
// A missing go.sum file is treated as if empty.
func TidyGoSum(keep map[module.Version]bool) (before, after []byte) {
	goSum.mu.Lock()
	defer goSum.mu.Unlock()
	before, err := lockedfile.Read(GoSumFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		base.Fatalf("reading go.sum: %v", err)
	}
	after = tidyGoSum(before, keep)
	return before, after
}

// tidyGoSum returns a tidy version of the go.sum file.
// The goSum lock must be held.
func tidyGoSum(data []byte, keep map[module.Version]bool) []byte {
	if !goSum.overwrite {
		// Incorporate any sums added by other processes in the meantime.
		// Add only the sums that we actually checked: the user may have edited or
		// truncated the file to remove erroneous hashes, and we shouldn't restore
		// them without good reason.
		goSum.m = make(map[module.Version][]string, len(goSum.m))
		readGoSum(goSum.m, GoSumFile, data)
		for ms, st := range goSum.status {
			if st.used && !sumInWorkspaceModulesLocked(ms.mod) {
				addModSumLocked(ms.mod, ms.sum)
			}
		}
	}

	mods := make([]module.Version, 0, len(goSum.m))
	for m := range goSum.m {
		mods = append(mods, m)
	}
	module.Sort(mods)

	var buf bytes.Buffer
	for _, m := range mods {
		list := goSum.m[m]
		sort.Strings(list)
		str.Uniq(&list)
		for _, h := range list {
			st := goSum.status[modSum{m, h}]
			if (!st.dirty || (st.used && keep[m])) && !sumInWorkspaceModulesLocked(m) {
				fmt.Fprintf(&buf, "%s %s %s\n", m.Path, m.Version, h)
			}
		}
	}
	return buf.Bytes()
}

func sumInWorkspaceModulesLocked(m module.Version) bool {
	for _, goSums := range goSum.w {
		if _, ok := goSums[m]; ok {
			return true
		}
	}
	return false
}

// TrimGoSum trims go.sum to contain only the modules needed for reproducible
// builds.
//
// keep is used to check whether a sum should be retained in go.mod. It should
// have entries for both module content sums and go.mod sums (version ends
// with "/go.mod").
func TrimGoSum(keep map[module.Version]bool) {
	goSum.mu.Lock()
	defer goSum.mu.Unlock()
	inited, err := initGoSum()
	if err != nil {
		base.Fatalf("%s", err)
	}
	if !inited {
		return
	}

	for m, hs := range goSum.m {
		if !keep[m] {
			for _, h := range hs {
				goSum.status[modSum{m, h}] = modSumStatus{used: false, dirty: true}
			}
			goSum.overwrite = true
		}
	}
}

const goSumMismatch = `

SECURITY ERROR
This download does NOT match an earlier download recorded in go.sum.
The bits may have been replaced on the origin server, or an attacker may
have intercepted the download attempt.

For more information, see 'go help module-auth'.
`

const sumdbMismatch = `

SECURITY ERROR
This download does NOT match the one reported by the checksum server.
The bits may have been replaced on the origin server, or an attacker may
have intercepted the download attempt.

For more information, see 'go help module-auth'.
`

const hashVersionMismatch = `

SECURITY WARNING
This download is listed in go.sum, but using an unknown hash algorithm.
The download cannot be verified.

For more information, see 'go help module-auth'.

`

var HelpModuleAuth = &base.Command{
	UsageLine: "module-auth",
	Short:     "module authentication using go.sum",
	Long: `
When the go command downloads a module zip file or go.mod file into the
module cache, it computes a cryptographic hash and compares it with a known
value to verify the file hasn't changed since it was first downloaded. Known
hashes are stored in a file in the module root directory named go.sum. Hashes
may also be downloaded from the checksum database depending on the values of
GOSUMDB, GOPRIVATE, and GONOSUMDB.

For details, see https://golang.org/ref/mod#authenticating.
`,
}

var HelpPrivate = &base.Command{
	UsageLine: "private",
	Short:     "configuration for downloading non-public code",
	Long: `
The go command defaults to downloading modules from the public Go module
mirror at proxy.golang.org. It also defaults to validating downloaded modules,
regardless of source, against the public Go checksum database at sum.golang.org.
These defaults work well for publicly available source code.

The GOPRIVATE environment variable controls which modules the go command
considers to be private (not available publicly) and should therefore not use
the proxy or checksum database. The variable is a comma-separated list of
glob patterns (in the syntax of Go's path.Match) of module path prefixes.
For example,

	GOPRIVATE=*.corp.example.com,rsc.io/private

causes the go command to treat as private any module with a path prefix
matching either pattern, including git.corp.example.com/xyzzy, rsc.io/private,
and rsc.io/private/quux.

For fine-grained control over module download and validation, the GONOPROXY
and GONOSUMDB environment variables accept the same kind of glob list
and override GOPRIVATE for the specific decision of whether to use the proxy
and checksum database, respectively.

For example, if a company ran a module proxy serving private modules,
users would configure go using:

	GOPRIVATE=*.corp.example.com
	GOPROXY=proxy.example.com
	GONOPROXY=none

The GOPRIVATE variable is also used to define the "public" and "private"
patterns for the GOVCS variable; see 'go help vcs'. For that usage,
GOPRIVATE applies even in GOPATH mode. In that case, it matches import paths
instead of module paths.

The 'go env -w' command (see 'go help env') can be used to set these variables
for future go command invocations.

For more details, see https://golang.org/ref/mod#private-modules.
`,
}
```