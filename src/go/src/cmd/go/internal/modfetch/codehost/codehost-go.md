Response: My thinking process to analyze the provided Go code and answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionalities of `codehost.go`, its usage, examples, and potential pitfalls. The context is the `cmd/go` tool, specifically the `modfetch` package, suggesting it's involved in fetching and managing Go modules.

2. **Initial Skim and Identify Key Types:** I quickly skim the code, looking for type definitions (structs, interfaces) and important constants. This gives a high-level overview of the data structures and concepts involved. I immediately see `Repo`, `Origin`, `Tags`, `RevInfo`, `RunError`, and the `Max*` constants.

3. **Focus on the `Repo` Interface:** The `Repo` interface seems central to the package's purpose. I analyze each of its methods:
    * `CheckReuse`:  This suggests caching and optimization by checking if cached information is still valid. The `Origin` struct is likely used to store this cached information.
    * `Tags`:  Fetching tags from a repository.
    * `Stat`: Getting information about a specific revision (commit, tag, branch).
    * `Latest`: Retrieving the latest revision on the default branch.
    * `ReadFile`: Reading a file at a specific revision.
    * `ReadZip`: Downloading a zip archive of a subdirectory at a specific revision.
    * `RecentTag`: Finding the most recent tag matching a prefix.
    * `DescendsFrom`: Checking if a revision or its ancestors have a specific tag.

4. **Analyze Supporting Types:**
    * `Origin`: This clearly represents the provenance of repository data, crucial for caching and `CheckReuse`. The fields indicate it tracks VCS type, URL, subdirectory, specific revisions (hash, ref), and potentially summaries of tags and the entire repo.
    * `Tags` and `Tag`: Simple structures for representing repository tags.
    * `RevInfo`:  Information about a specific revision, including its origin, name, short name, version, time, and associated tags.
    * `UnknownRevisionError` and `ErrNoCommits`: Custom error types for specific scenarios.

5. **Examine Utility Functions:** I look at the standalone functions:
    * `AllHex`, `ShortenSHA1`:  These seem related to Git commit hashes and their representation, potentially for pseudo-versions.
    * `WorkDir`:  This is clearly about managing a cache directory for repositories. The locking mechanism (`lockedfile`) suggests concurrency control.
    * `Run`, `RunWithArgs`:  These functions execute external commands, likely for interacting with VCS tools. The `RunError` struct handles errors from these commands.

6. **Infer Functionality and Go Features:** Based on the types and methods, I can infer the core functionalities:
    * **Abstraction over different code hosting sources:** The `Repo` interface provides a unified way to interact with Git repositories, remote servers, etc.
    * **Caching and Optimization:** The `Origin` and `CheckReuse` mechanism are clear indicators of caching to avoid redundant network requests and computations.
    * **Version Control Interaction:** The methods like `Tags`, `Stat`, `Latest`, `ReadFile`, `ReadZip` are typical operations performed on version control systems.
    * **Support for Go Modules:** The presence of `golang.org/x/mod/module` and the file size limits for `go.mod` and `LICENSE` strongly suggest this code is used for fetching and managing Go modules.
    * **Command Execution:** The `Run` functions are essential for interacting with underlying VCS tools like `git`.

7. **Construct Examples:** I choose key functionalities and create simple Go code snippets to illustrate their usage. I focus on `Repo`, `Origin`, and the `Run` function, as these are central. I make reasonable assumptions about the input and output for the examples.

8. **Identify Command-Line Argument Handling (Indirectly):** While the code doesn't directly parse command-line arguments, the `WorkDir` function uses `cfg.GOMODCACHE`, which is often configured via environment variables or command-line flags. I explain this indirect relationship.

9. **Pinpoint Potential User Errors:** I think about how developers might misuse or misunderstand the provided functionality. The main points I identify are:
    * **Modifying returned values:** The documentation explicitly states not to modify returned values from `Repo` methods.
    * **Incorrect `Origin` usage:** Misunderstanding how `Origin` works with `CheckReuse` could lead to unexpected caching behavior.
    * **Assumptions about `Latest`:** Different VCS might have different interpretations of the "default branch."

10. **Review and Refine:** I reread my analysis and examples to ensure clarity, accuracy, and completeness. I check if I've addressed all parts of the original request. I ensure the language is precise and avoids jargon where possible.

This structured approach, starting with a high-level understanding and gradually drilling down into specifics, allows me to effectively analyze the code and provide a comprehensive answer to the request. The focus on key types and their interactions is crucial for understanding the overall design and purpose of the package.
这段代码是 Go 语言 `cmd/go` 工具中 `internal/modfetch/codehost` 包的一部分。它的主要功能是定义了与代码托管服务交互的接口 `Repo` 以及一些辅助结构体和函数，用于实现 Go 模块的发现、下载和版本管理。

以下是其具体功能列表：

**核心接口和类型定义：**

1. **`Repo` 接口:** 定义了与代码托管服务交互的抽象方法。不同的代码托管服务（如 GitHub, GitLab, Bitbucket 或本地仓库）可以通过实现这个接口来被 `go` 命令所支持。
2. **`Origin` 结构体:**  描述了从代码托管服务获取的模块信息的来源，用于缓存和重用机制。它记录了 VCS 类型、仓库 URL、子目录、特定提交的哈希值、标签信息等。
3. **`Tags` 结构体:**  表示代码仓库中可用的标签列表，包含 `Origin` 信息和 `Tag` 列表。
4. **`Tag` 结构体:**  表示单个标签，包含标签名和内容哈希值（如果可用）。
5. **`RevInfo` 结构体:**  描述了代码仓库中的一个特定版本（revision），包含其 `Origin`、完整 ID、缩短的 ID、版本号、提交时间以及相关的标签。
6. **`UnknownRevisionError` 结构体:**  表示找不到指定 revision 的错误。
7. **`ErrNoCommits` 错误变量:**  表示仓库没有提交记录的错误。
8. **`RunError` 结构体:**  表示执行外部命令（如 `git`）时发生的错误，包含命令、错误信息和标准错误输出。

**核心功能：**

1. **代码托管源抽象:**  通过 `Repo` 接口，将 `go` 命令与具体的代码托管服务解耦，使得可以支持多种不同的代码托管平台。
2. **版本控制操作:**  `Repo` 接口定义了获取标签列表 (`Tags`)、获取特定版本信息 (`Stat`)、获取最新版本信息 (`Latest`)、读取文件 (`ReadFile`)、下载 ZIP 包 (`ReadZip`)、查找最近标签 (`RecentTag`) 以及判断版本是否包含特定标签 (`DescendsFrom`) 等操作，涵盖了与版本控制系统交互的常见需求。
3. **缓存和重用:**  `CheckReuse` 方法和 `Origin` 结构体用于实现缓存机制。`go` 命令可以检查之前获取的模块信息是否仍然有效，避免重复的网络请求和计算。
4. **ZIP 下载:** `ReadZip` 方法用于下载指定版本和子目录的 ZIP 压缩包，这是获取模块代码的一种常见方式。
5. **伪版本支持:**  `ShortenSHA1` 函数用于缩短 SHA1 哈希值，这在生成 Go 模块的伪版本时使用。
6. **工作目录管理:** `WorkDir` 函数负责创建和管理用于存储下载的仓库数据的本地缓存目录。它使用文件锁来保证并发安全。
7. **外部命令执行:** `Run` 和 `RunWithArgs` 函数用于执行外部命令，例如调用 `git` 命令来与 Git 仓库进行交互。

**如果你能推理出它是什么go语言功能的实现，请用go代码举例说明:**

这段代码是 Go 语言模块系统 (Go Modules) 中用于从代码托管平台获取模块信息和代码的关键部分。它定义了与各种版本控制系统和代码托管服务交互的抽象层。

**代码示例（假设我们有一个实现了 `Repo` 接口的 `gitRepo` 类型）：**

```go
package main

import (
	"context"
	"fmt"
	"time"

	"go/src/cmd/go/internal/modfetch/codehost"
)

// 假设 gitRepo 实现了 codehost.Repo 接口 (这里仅为示例，省略了具体实现)
type gitRepo struct {
	url string
}

func (r *gitRepo) CheckReuse(ctx context.Context, old *codehost.Origin, subdir string) error {
	// ... 实现检查 Origin 是否仍然有效 ...
	return nil
}

func (r *gitRepo) Tags(ctx context.Context, prefix string) (*codehost.Tags, error) {
	// ... 实现获取标签列表 ...
	return &codehost.Tags{
		List: []codehost.Tag{
			{Name: "v1.0.0", Hash: "abcdef123456"},
			{Name: "v1.0.1", Hash: "fedcba987654"},
		},
	}, nil
}

func (r *gitRepo) Stat(ctx context.Context, rev string) (*codehost.RevInfo, error) {
	// ... 实现获取指定 revision 的信息 ...
	return &codehost.RevInfo{
		Name:    rev,
		Short:   rev[:7],
		Version: rev,
		Time:    time.Now(),
		Tags:    []string{"v1.0.0"},
	}, nil
}

func (r *gitRepo) Latest(ctx context.Context) (*codehost.RevInfo, error) {
	// ... 实现获取最新 revision 的信息 ...
	return &codehost.RevInfo{
		Name:    "main",
		Short:   "main",
		Version: "main",
		Time:    time.Now(),
		Tags:    []string{},
	}, nil
}

func (r *gitRepo) ReadFile(ctx context.Context, rev, file string, maxSize int64) ([]byte, error) {
	// ... 实现读取文件内容 ...
	if file == "go.mod" {
		return []byte("module example.com/my/module\n\ngo 1.16"), nil
	}
	return nil, fmt.Errorf("file not found")
}

func (r *gitRepo) ReadZip(ctx context.Context, rev, subdir string, maxSize int64) (io.ReadCloser, error) {
	// ... 实现下载 ZIP 包 ...
	return nil, fmt.Errorf("not implemented")
}

func (r *gitRepo) RecentTag(ctx context.Context, rev, prefix string, allowed func(tag string) bool) (string, error) {
	// ... 实现查找最近标签 ...
	return "v1.0.1", nil
}

func (r *gitRepo) DescendsFrom(ctx context.Context, rev, tag string) (bool, error) {
	// ... 实现判断版本是否包含特定标签 ...
	return true, nil
}

func main() {
	ctx := context.Background()
	repo := &gitRepo{url: "https://github.com/example/repo"}

	tags, err := repo.Tags(ctx, "v")
	if err != nil {
		fmt.Println("Error getting tags:", err)
	} else {
		fmt.Println("Tags:", tags.List)
	}

	revInfo, err := repo.Stat(ctx, "v1.0.0")
	if err != nil {
		fmt.Println("Error getting revision info:", err)
	} else {
		fmt.Println("Revision Info:", revInfo)
	}

	fileContent, err := repo.ReadFile(ctx, "v1.0.0", "go.mod", 1024)
	if err != nil {
		fmt.Println("Error reading file:", err)
	} else {
		fmt.Println("go.mod content:\n", string(fileContent))
	}
}
```

**假设的输入与输出：**

在上面的示例中，假设 `gitRepo` 针对 URL `https://github.com/example/repo` 实现了 `Repo` 接口。

**输入：**

* 调用 `repo.Tags(ctx, "v")`
* 调用 `repo.Stat(ctx, "v1.0.0")`
* 调用 `repo.ReadFile(ctx, "v1.0.0", "go.mod", 1024)`

**输出：**

```
Tags: [{v1.0.0 abcdef123456} {v1.0.1 fedcba987654}]
Revision Info: &{<nil> v1.0.0 v1.0 v1.0.0 2023-10-27 10:00:00 +0000 UTC [v1.0.0]}
go.mod content:
 module example.com/my/module

go 1.16
```

**如果涉及命令行参数的具体处理，请详细介绍一下：**

这段代码本身并不直接处理命令行参数。但是，它所使用的 `cmd/go/internal/cfg` 包会处理 Go 命令的配置，这些配置通常通过环境变量或命令行参数进行设置。

例如，`WorkDir` 函数使用了 `cfg.GOMODCACHE`，这个变量的值通常由环境变量 `GOMODCACHE` 或通过 `go env -w GOMODCACHE=/path/to/cache` 命令设置。

当执行 `go get` 或 `go mod download` 等命令时，`go` 命令会解析命令行参数，读取环境变量，并将相关配置信息传递给 `modfetch` 包，最终影响 `codehost` 包的行为，例如确定缓存目录的位置。

**如果有哪些使用者易犯错的点，请举例说明：**

1. **修改 `Repo` 接口方法返回的值:**  `Repo` 接口的文档明确指出调用者不应该修改返回的值，因为这些值可能被缓存和共享。例如，修改 `Tags().List` 的内容可能会导致意外的行为。

   ```go
   tags, _ := repo.Tags(ctx, "v")
   if len(tags.List) > 0 {
       tags.List[0].Name = "modified_tag" // 错误的做法，可能会影响其他地方使用缓存的数据
   }
   ```

2. **不正确地使用 `Origin` 进行缓存重用:**  使用者可能会错误地认为只要 `Origin` 中的某些字段相同就可以重用缓存，但 `CheckReuse` 方法的实现可能需要检查更复杂的状态。

   ```go
   // 假设从之前的操作中获取了 oldOrigin
   err := repo.CheckReuse(ctx, oldOrigin, "")
   if err == nil {
       // 错误地认为可以无条件重用缓存，但实际情况可能更复杂
       // ... 使用缓存的数据 ...
   }
   ```

3. **对 `Latest` 方法的理解存在偏差:**  不同的代码托管服务对于“最新”的理解可能不同。例如，对于 Git 仓库，它可能是默认分支的最新提交，但对于其他系统，可能有不同的定义。使用者需要理解特定 `Repo` 实现的 `Latest` 方法的含义。

4. **假设 `ReadFile` 或 `ReadZip` 总是返回完整的内容:**  `ReadFile` 和 `ReadZip` 方法都接受 `maxSize` 参数，这意味着它们可能会在达到大小限制时停止读取。使用者需要处理返回的数据可能不完整的情况。

   ```go
   content, err := repo.ReadFile(ctx, "v1.0.0", "large_file.txt", 1024)
   if err == nil {
       // content 的长度可能小于文件的实际大小
       fmt.Println("Read", len(content), "bytes")
   }
   ```

这段代码是 Go 模块系统中一个重要的组成部分，它通过抽象和接口定义，为 `go` 命令提供了与各种代码托管服务交互的能力，是实现模块发现、下载和版本管理的基础。理解其功能和潜在的误用可以帮助开发者更好地理解和使用 Go 模块系统。

Prompt: 
```
这是路径为go/src/cmd/go/internal/modfetch/codehost/codehost.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package codehost defines the interface implemented by a code hosting source,
// along with support code for use by implementations.
package codehost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cmd/go/internal/cfg"
	"cmd/go/internal/lockedfile"
	"cmd/go/internal/str"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// Downloaded size limits.
const (
	MaxGoMod   = 16 << 20  // maximum size of go.mod file
	MaxLICENSE = 16 << 20  // maximum size of LICENSE file
	MaxZipFile = 500 << 20 // maximum size of downloaded zip file
)

// A Repo represents a code hosting source.
// Typical implementations include local version control repositories,
// remote version control servers, and code hosting sites.
//
// A Repo must be safe for simultaneous use by multiple goroutines,
// and callers must not modify returned values, which may be cached and shared.
type Repo interface {
	// CheckReuse checks whether the old origin information
	// remains up to date. If so, whatever cached object it was
	// taken from can be reused.
	// The subdir gives subdirectory name where the module root is expected to be found,
	// "" for the root or "sub/dir" for a subdirectory (no trailing slash).
	CheckReuse(ctx context.Context, old *Origin, subdir string) error

	// Tags lists all tags with the given prefix.
	Tags(ctx context.Context, prefix string) (*Tags, error)

	// Stat returns information about the revision rev.
	// A revision can be any identifier known to the underlying service:
	// commit hash, branch, tag, and so on.
	Stat(ctx context.Context, rev string) (*RevInfo, error)

	// Latest returns the latest revision on the default branch,
	// whatever that means in the underlying implementation.
	Latest(ctx context.Context) (*RevInfo, error)

	// ReadFile reads the given file in the file tree corresponding to revision rev.
	// It should refuse to read more than maxSize bytes.
	//
	// If the requested file does not exist it should return an error for which
	// os.IsNotExist(err) returns true.
	ReadFile(ctx context.Context, rev, file string, maxSize int64) (data []byte, err error)

	// ReadZip downloads a zip file for the subdir subdirectory
	// of the given revision to a new file in a given temporary directory.
	// It should refuse to read more than maxSize bytes.
	// It returns a ReadCloser for a streamed copy of the zip file.
	// All files in the zip file are expected to be
	// nested in a single top-level directory, whose name is not specified.
	ReadZip(ctx context.Context, rev, subdir string, maxSize int64) (zip io.ReadCloser, err error)

	// RecentTag returns the most recent tag on rev or one of its predecessors
	// with the given prefix. allowed may be used to filter out unwanted versions.
	RecentTag(ctx context.Context, rev, prefix string, allowed func(tag string) bool) (tag string, err error)

	// DescendsFrom reports whether rev or any of its ancestors has the given tag.
	//
	// DescendsFrom must return true for any tag returned by RecentTag for the
	// same revision.
	DescendsFrom(ctx context.Context, rev, tag string) (bool, error)
}

// An Origin describes the provenance of a given repo method result.
// It can be passed to CheckReuse (usually in a different go command invocation)
// to see whether the result remains up-to-date.
type Origin struct {
	VCS    string `json:",omitempty"` // "git" etc
	URL    string `json:",omitempty"` // URL of repository
	Subdir string `json:",omitempty"` // subdirectory in repo

	Hash string `json:",omitempty"` // commit hash or ID

	// If TagSum is non-empty, then the resolution of this module version
	// depends on the set of tags present in the repo, specifically the tags
	// of the form TagPrefix + a valid semver version.
	// If the matching repo tags and their commit hashes still hash to TagSum,
	// the Origin is still valid (at least as far as the tags are concerned).
	// The exact checksum is up to the Repo implementation; see (*gitRepo).Tags.
	TagPrefix string `json:",omitempty"`
	TagSum    string `json:",omitempty"`

	// If Ref is non-empty, then the resolution of this module version
	// depends on Ref resolving to the revision identified by Hash.
	// If Ref still resolves to Hash, the Origin is still valid (at least as far as Ref is concerned).
	// For Git, the Ref is a full ref like "refs/heads/main" or "refs/tags/v1.2.3",
	// and the Hash is the Git object hash the ref maps to.
	// Other VCS might choose differently, but the idea is that Ref is the name
	// with a mutable meaning while Hash is a name with an immutable meaning.
	Ref string `json:",omitempty"`

	// If RepoSum is non-empty, then the resolution of this module version
	// failed due to the repo being available but the version not being present.
	// This depends on the entire state of the repo, which RepoSum summarizes.
	// For Git, this is a hash of all the refs and their hashes.
	RepoSum string `json:",omitempty"`
}

// A Tags describes the available tags in a code repository.
type Tags struct {
	Origin *Origin
	List   []Tag
}

// A Tag describes a single tag in a code repository.
type Tag struct {
	Name string
	Hash string // content hash identifying tag's content, if available
}

// isOriginTag reports whether tag should be preserved
// in the Tags method's Origin calculation.
// We can safely ignore tags that are not look like pseudo-versions,
// because ../coderepo.go's (*codeRepo).Versions ignores them too.
// We can also ignore non-semver tags, but we have to include semver
// tags with extra suffixes, because the pseudo-version base finder uses them.
func isOriginTag(tag string) bool {
	// modfetch.(*codeRepo).Versions uses Canonical == tag,
	// but pseudo-version calculation has a weaker condition that
	// the canonical is a prefix of the tag.
	// Include those too, so that if any new one appears, we'll invalidate the cache entry.
	// This will lead to spurious invalidation of version list results,
	// but tags of this form being created should be fairly rare
	// (and invalidate pseudo-version results anyway).
	c := semver.Canonical(tag)
	return c != "" && strings.HasPrefix(tag, c) && !module.IsPseudoVersion(tag)
}

// A RevInfo describes a single revision in a source code repository.
type RevInfo struct {
	Origin  *Origin
	Name    string    // complete ID in underlying repository
	Short   string    // shortened ID, for use in pseudo-version
	Version string    // version used in lookup
	Time    time.Time // commit time
	Tags    []string  // known tags for commit
}

// UnknownRevisionError is an error equivalent to fs.ErrNotExist, but for a
// revision rather than a file.
type UnknownRevisionError struct {
	Rev string
}

func (e *UnknownRevisionError) Error() string {
	return "unknown revision " + e.Rev
}
func (UnknownRevisionError) Is(err error) bool {
	return err == fs.ErrNotExist
}

// ErrNoCommits is an error equivalent to fs.ErrNotExist indicating that a given
// repository or module contains no commits.
var ErrNoCommits error = noCommitsError{}

type noCommitsError struct{}

func (noCommitsError) Error() string {
	return "no commits"
}
func (noCommitsError) Is(err error) bool {
	return err == fs.ErrNotExist
}

// AllHex reports whether the revision rev is entirely lower-case hexadecimal digits.
func AllHex(rev string) bool {
	for i := 0; i < len(rev); i++ {
		c := rev[i]
		if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

// ShortenSHA1 shortens a SHA1 hash (40 hex digits) to the canonical length
// used in pseudo-versions (12 hex digits).
func ShortenSHA1(rev string) string {
	if AllHex(rev) && len(rev) == 40 {
		return rev[:12]
	}
	return rev
}

// WorkDir returns the name of the cached work directory to use for the
// given repository type and name.
func WorkDir(ctx context.Context, typ, name string) (dir, lockfile string, err error) {
	if cfg.GOMODCACHE == "" {
		return "", "", fmt.Errorf("neither GOPATH nor GOMODCACHE are set")
	}

	// We name the work directory for the SHA256 hash of the type and name.
	// We intentionally avoid the actual name both because of possible
	// conflicts with valid file system paths and because we want to ensure
	// that one checkout is never nested inside another. That nesting has
	// led to security problems in the past.
	if strings.Contains(typ, ":") {
		return "", "", fmt.Errorf("codehost.WorkDir: type cannot contain colon")
	}
	key := typ + ":" + name
	dir = filepath.Join(cfg.GOMODCACHE, "cache/vcs", fmt.Sprintf("%x", sha256.Sum256([]byte(key))))

	xLog, buildX := cfg.BuildXWriter(ctx)
	if buildX {
		fmt.Fprintf(xLog, "mkdir -p %s # %s %s\n", filepath.Dir(dir), typ, name)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0777); err != nil {
		return "", "", err
	}

	lockfile = dir + ".lock"
	if buildX {
		fmt.Fprintf(xLog, "# lock %s\n", lockfile)
	}

	unlock, err := lockedfile.MutexAt(lockfile).Lock()
	if err != nil {
		return "", "", fmt.Errorf("codehost.WorkDir: can't find or create lock file: %v", err)
	}
	defer unlock()

	data, err := os.ReadFile(dir + ".info")
	info, err2 := os.Stat(dir)
	if err == nil && err2 == nil && info.IsDir() {
		// Info file and directory both already exist: reuse.
		have := strings.TrimSuffix(string(data), "\n")
		if have != key {
			return "", "", fmt.Errorf("%s exists with wrong content (have %q want %q)", dir+".info", have, key)
		}
		if buildX {
			fmt.Fprintf(xLog, "# %s for %s %s\n", dir, typ, name)
		}
		return dir, lockfile, nil
	}

	// Info file or directory missing. Start from scratch.
	if xLog != nil {
		fmt.Fprintf(xLog, "mkdir -p %s # %s %s\n", dir, typ, name)
	}
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0777); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(dir+".info", []byte(key), 0666); err != nil {
		os.RemoveAll(dir)
		return "", "", err
	}
	return dir, lockfile, nil
}

type RunError struct {
	Cmd      string
	Err      error
	Stderr   []byte
	HelpText string
}

func (e *RunError) Error() string {
	text := e.Cmd + ": " + e.Err.Error()
	stderr := bytes.TrimRight(e.Stderr, "\n")
	if len(stderr) > 0 {
		text += ":\n\t" + strings.ReplaceAll(string(stderr), "\n", "\n\t")
	}
	if len(e.HelpText) > 0 {
		text += "\n" + e.HelpText
	}
	return text
}

var dirLock sync.Map

type RunArgs struct {
	cmdline []any    // the command to run
	dir     string   // the directory to run the command in
	local   bool     // true if the VCS information is local
	env     []string // environment variables for the command
	stdin   io.Reader
}

// Run runs the command line in the given directory
// (an empty dir means the current directory).
// It returns the standard output and, for a non-zero exit,
// a *RunError indicating the command, exit status, and standard error.
// Standard error is unavailable for commands that exit successfully.
func Run(ctx context.Context, dir string, cmdline ...any) ([]byte, error) {
	return run(ctx, RunArgs{cmdline: cmdline, dir: dir})
}

// RunWithArgs is the same as Run but it also accepts additional arguments.
func RunWithArgs(ctx context.Context, args RunArgs) ([]byte, error) {
	return run(ctx, args)
}

// bashQuoter escapes characters that have special meaning in double-quoted strings in the bash shell.
// See https://www.gnu.org/software/bash/manual/html_node/Double-Quotes.html.
var bashQuoter = strings.NewReplacer(`"`, `\"`, `$`, `\$`, "`", "\\`", `\`, `\\`)

func run(ctx context.Context, args RunArgs) ([]byte, error) {
	if args.dir != "" {
		muIface, ok := dirLock.Load(args.dir)
		if !ok {
			muIface, _ = dirLock.LoadOrStore(args.dir, new(sync.Mutex))
		}
		mu := muIface.(*sync.Mutex)
		mu.Lock()
		defer mu.Unlock()
	}

	cmd := str.StringList(args.cmdline...)
	if os.Getenv("TESTGOVCSREMOTE") == "panic" && !args.local {
		panic(fmt.Sprintf("use of remote vcs: %v", cmd))
	}
	if xLog, ok := cfg.BuildXWriter(ctx); ok {
		text := new(strings.Builder)
		if args.dir != "" {
			text.WriteString("cd ")
			text.WriteString(args.dir)
			text.WriteString("; ")
		}
		for i, arg := range cmd {
			if i > 0 {
				text.WriteByte(' ')
			}
			switch {
			case strings.ContainsAny(arg, "'"):
				// Quote args that could be mistaken for quoted args.
				text.WriteByte('"')
				text.WriteString(bashQuoter.Replace(arg))
				text.WriteByte('"')
			case strings.ContainsAny(arg, "$`\\*?[\"\t\n\v\f\r \u0085\u00a0"):
				// Quote args that contain special characters, glob patterns, or spaces.
				text.WriteByte('\'')
				text.WriteString(arg)
				text.WriteByte('\'')
			default:
				text.WriteString(arg)
			}
		}
		fmt.Fprintf(xLog, "%s\n", text)
		start := time.Now()
		defer func() {
			fmt.Fprintf(xLog, "%.3fs # %s\n", time.Since(start).Seconds(), text)
		}()
	}
	// TODO: Impose limits on command output size.
	// TODO: Set environment to get English error messages.
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.Cancel = func() error { return c.Process.Signal(os.Interrupt) }
	c.Dir = args.dir
	c.Stdin = args.stdin
	c.Stderr = &stderr
	c.Stdout = &stdout
	c.Env = append(c.Environ(), args.env...)
	err := c.Run()
	if err != nil {
		err = &RunError{Cmd: strings.Join(cmd, " ") + " in " + args.dir, Stderr: stderr.Bytes(), Err: err}
	}
	return stdout.Bytes(), err
}

"""



```